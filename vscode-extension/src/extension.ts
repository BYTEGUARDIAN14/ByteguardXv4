import * as vscode from 'vscode';
import { ByteGuardXProvider } from './provider';
import { SecurityDiagnosticCollection } from './diagnostics';
import { SecurityTreeDataProvider } from './treeView';
import { ByteGuardXAPI } from './api';
import { SecurityHeatmapProvider } from './heatmap';
import { CodeFlowAnalyzer } from './codeflow';
import { AIPatternLearner } from './ailearning';

let diagnosticCollection: vscode.DiagnosticCollection;
let securityProvider: ByteGuardXProvider;
let treeDataProvider: SecurityTreeDataProvider;

export function activate(context: vscode.ExtensionContext) {
    console.log('ByteGuardX extension is now active!');

    // Initialize components
    diagnosticCollection = vscode.languages.createDiagnosticCollection('byteguardx');
    const api = new ByteGuardXAPI();
    securityProvider = new ByteGuardXProvider(api, diagnosticCollection);
    treeDataProvider = new SecurityTreeDataProvider();

    // Register tree view
    vscode.window.createTreeView('byteguardxFindings', {
        treeDataProvider: treeDataProvider,
        showCollapseAll: true
    });

    // Register commands
    const commands = [
        vscode.commands.registerCommand('byteguardx.scanFile', () => scanCurrentFile()),
        vscode.commands.registerCommand('byteguardx.scanWorkspace', () => scanWorkspace()),
        vscode.commands.registerCommand('byteguardx.scanSelection', () => scanSelection()),
        vscode.commands.registerCommand('byteguardx.showReport', () => showSecurityReport()),
        vscode.commands.registerCommand('byteguardx.clearFindings', () => clearFindings()),
        vscode.commands.registerCommand('byteguardx.configure', () => openConfiguration()),
    ];

    // Register event listeners
    const eventListeners = [
        vscode.workspace.onDidSaveTextDocument(onDocumentSave),
        vscode.window.onDidChangeActiveTextEditor(onActiveEditorChange),
        vscode.workspace.onDidChangeConfiguration(onConfigurationChange),
    ];

    // Add to context subscriptions
    context.subscriptions.push(
        diagnosticCollection,
        ...commands,
        ...eventListeners
    );

    // Set context for when findings exist
    vscode.commands.executeCommand('setContext', 'byteguardx.hasFindings', false);

    // Show welcome message
    showWelcomeMessage();
}

async function scanCurrentFile() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('No active file to scan');
        return;
    }

    const document = editor.document;
    if (document.isUntitled) {
        vscode.window.showWarningMessage('Please save the file before scanning');
        return;
    }

    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'Scanning file for security issues...',
        cancellable: true
    }, async (progress, token) => {
        try {
            const findings = await securityProvider.scanFile(document.uri.fsPath, document.getText());
            
            if (findings.length > 0) {
                treeDataProvider.updateFindings(findings);
                vscode.commands.executeCommand('setContext', 'byteguardx.hasFindings', true);
                
                const criticalCount = findings.filter(f => f.severity === 'critical').length;
                const highCount = findings.filter(f => f.severity === 'high').length;
                
                if (criticalCount > 0) {
                    vscode.window.showErrorMessage(
                        `Found ${criticalCount} critical security issue(s) in ${document.fileName}`
                    );
                } else if (highCount > 0) {
                    vscode.window.showWarningMessage(
                        `Found ${highCount} high severity security issue(s) in ${document.fileName}`
                    );
                } else {
                    vscode.window.showInformationMessage(
                        `Found ${findings.length} security issue(s) in ${document.fileName}`
                    );
                }
            } else {
                vscode.window.showInformationMessage('No security issues found!');
            }
        } catch (error) {
            vscode.window.showErrorMessage(`Scan failed: ${error}`);
        }
    });
}

async function scanWorkspace() {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) {
        vscode.window.showWarningMessage('No workspace folder open');
        return;
    }

    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'Scanning workspace for security issues...',
        cancellable: true
    }, async (progress, token) => {
        try {
            const allFindings: any[] = [];
            const config = vscode.workspace.getConfiguration('byteguardx');
            const excludePatterns = config.get<string[]>('excludePatterns', []);

            for (const folder of workspaceFolders) {
                const files = await vscode.workspace.findFiles(
                    new vscode.RelativePattern(folder, '**/*.{py,js,jsx,ts,tsx,java,cpp,c,h,cs,php,rb,go,rs}'),
                    new vscode.RelativePattern(folder, `{${excludePatterns.join(',')}}`)
                );

                for (let i = 0; i < files.length; i++) {
                    if (token.isCancellationRequested) {
                        return;
                    }

                    const file = files[i];
                    progress.report({
                        message: `Scanning ${file.fsPath}...`,
                        increment: (100 / files.length)
                    });

                    try {
                        const document = await vscode.workspace.openTextDocument(file);
                        const findings = await securityProvider.scanFile(file.fsPath, document.getText());
                        allFindings.push(...findings);
                    } catch (error) {
                        console.error(`Failed to scan ${file.fsPath}:`, error);
                    }
                }
            }

            if (allFindings.length > 0) {
                treeDataProvider.updateFindings(allFindings);
                vscode.commands.executeCommand('setContext', 'byteguardx.hasFindings', true);
                
                const criticalCount = allFindings.filter(f => f.severity === 'critical').length;
                const highCount = allFindings.filter(f => f.severity === 'high').length;
                
                vscode.window.showInformationMessage(
                    `Workspace scan complete: ${allFindings.length} issues found (${criticalCount} critical, ${highCount} high)`
                );
            } else {
                vscode.window.showInformationMessage('Workspace scan complete: No security issues found!');
            }
        } catch (error) {
            vscode.window.showErrorMessage(`Workspace scan failed: ${error}`);
        }
    });
}

async function scanSelection() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('No active editor');
        return;
    }

    const selection = editor.selection;
    if (selection.isEmpty) {
        vscode.window.showWarningMessage('No text selected');
        return;
    }

    const selectedText = editor.document.getText(selection);
    
    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'Scanning selection for security issues...',
        cancellable: false
    }, async () => {
        try {
            const findings = await securityProvider.scanText(selectedText, editor.document.uri.fsPath);
            
            if (findings.length > 0) {
                // Filter findings to only those within the selection
                const selectionStart = editor.document.offsetAt(selection.start);
                const selectionEnd = editor.document.offsetAt(selection.end);
                
                const filteredFindings = findings.filter(finding => {
                    const findingOffset = editor.document.offsetAt(new vscode.Position(finding.line - 1, 0));
                    return findingOffset >= selectionStart && findingOffset <= selectionEnd;
                });

                if (filteredFindings.length > 0) {
                    treeDataProvider.updateFindings(filteredFindings);
                    vscode.commands.executeCommand('setContext', 'byteguardx.hasFindings', true);
                    vscode.window.showInformationMessage(`Found ${filteredFindings.length} security issue(s) in selection`);
                } else {
                    vscode.window.showInformationMessage('No security issues found in selection');
                }
            } else {
                vscode.window.showInformationMessage('No security issues found in selection');
            }
        } catch (error) {
            vscode.window.showErrorMessage(`Selection scan failed: ${error}`);
        }
    });
}

async function showSecurityReport() {
    const findings = treeDataProvider.getAllFindings();
    
    if (findings.length === 0) {
        vscode.window.showInformationMessage('No security findings to report. Run a scan first.');
        return;
    }

    // Create and show report in new document
    const reportContent = generateReportContent(findings);
    const doc = await vscode.workspace.openTextDocument({
        content: reportContent,
        language: 'markdown'
    });
    
    await vscode.window.showTextDocument(doc);
}

function generateReportContent(findings: any[]): string {
    const severityCounts = {
        critical: findings.filter(f => f.severity === 'critical').length,
        high: findings.filter(f => f.severity === 'high').length,
        medium: findings.filter(f => f.severity === 'medium').length,
        low: findings.filter(f => f.severity === 'low').length
    };

    let report = `# ByteGuardX Security Report

Generated: ${new Date().toLocaleString()}

## Summary

- **Total Issues**: ${findings.length}
- **Critical**: ${severityCounts.critical}
- **High**: ${severityCounts.high}
- **Medium**: ${severityCounts.medium}
- **Low**: ${severityCounts.low}

## Findings

`;

    findings.forEach((finding, index) => {
        report += `### ${index + 1}. ${finding.description}

- **Severity**: ${finding.severity.toUpperCase()}
- **Type**: ${finding.type}
- **File**: ${finding.file}
- **Line**: ${finding.line}

\`\`\`
${finding.context || 'No context available'}
\`\`\`

**Recommendation**: ${finding.recommendation || 'No recommendation available'}

---

`;
    });

    return report;
}

function clearFindings() {
    diagnosticCollection.clear();
    treeDataProvider.clearFindings();
    vscode.commands.executeCommand('setContext', 'byteguardx.hasFindings', false);
    vscode.window.showInformationMessage('All security findings cleared');
}

function openConfiguration() {
    vscode.commands.executeCommand('workbench.action.openSettings', 'byteguardx');
}

async function onDocumentSave(document: vscode.TextDocument) {
    const config = vscode.workspace.getConfiguration('byteguardx');
    const autoScanOnSave = config.get<boolean>('autoScanOnSave', false);
    
    if (autoScanOnSave && isSupportedFile(document.uri.fsPath)) {
        try {
            const findings = await securityProvider.scanFile(document.uri.fsPath, document.getText());
            if (findings.length > 0) {
                const criticalCount = findings.filter(f => f.severity === 'critical').length;
                if (criticalCount > 0) {
                    vscode.window.showWarningMessage(
                        `${criticalCount} critical security issue(s) found in ${document.fileName}`
                    );
                }
            }
        } catch (error) {
            console.error('Auto-scan failed:', error);
        }
    }
}

function onActiveEditorChange(editor: vscode.TextEditor | undefined) {
    if (editor && isSupportedFile(editor.document.uri.fsPath)) {
        // Update decorations for the active file
        securityProvider.updateDecorations(editor);
    }
}

function onConfigurationChange(event: vscode.ConfigurationChangeEvent) {
    if (event.affectsConfiguration('byteguardx')) {
        // Reload configuration
        securityProvider.reloadConfiguration();
    }
}

function isSupportedFile(filePath: string): boolean {
    const supportedExtensions = ['.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.cpp', '.c', '.h', '.cs', '.php', '.rb', '.go', '.rs'];
    return supportedExtensions.some(ext => filePath.endsWith(ext));
}

function showWelcomeMessage() {
    const config = vscode.workspace.getConfiguration('byteguardx');
    const apiKey = config.get<string>('apiKey', '');
    
    if (!apiKey) {
        vscode.window.showInformationMessage(
            'Welcome to ByteGuardX! Configure your API key to get started.',
            'Configure'
        ).then(selection => {
            if (selection === 'Configure') {
                openConfiguration();
            }
        });
    }
}

export function deactivate() {
    if (diagnosticCollection) {
        diagnosticCollection.dispose();
    }
}
