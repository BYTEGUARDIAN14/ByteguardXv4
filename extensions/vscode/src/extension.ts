/**
 * ByteGuardX VS Code Extension
 * AI-powered security vulnerability scanner integration
 */

import * as vscode from 'vscode';
import axios from 'axios';
import { ByteGuardXProvider } from './provider';
import { SecurityDiagnostics } from './diagnostics';
import { FixProvider } from './fixProvider';

interface ScanResult {
    scan_id: string;
    status: string;
    findings: Finding[];
    total_findings: number;
    critical_findings: number;
    high_findings: number;
    medium_findings: number;
    low_findings: number;
}

interface Finding {
    id: string;
    vulnerability_type: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    title: string;
    description: string;
    file_path: string;
    line_number: number;
    code_snippet: string;
    confidence_score: number;
    scanner_type: string;
}

export function activate(context: vscode.ExtensionContext) {
    console.log('ByteGuardX extension is now active!');

    // Initialize providers
    const provider = new ByteGuardXProvider(context);
    const diagnostics = new SecurityDiagnostics();
    const fixProvider = new FixProvider();

    // Register tree data provider
    vscode.window.registerTreeDataProvider('byteguardxResults', provider);

    // Register commands
    const scanFileCommand = vscode.commands.registerCommand('byteguardx.scanFile', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showWarningMessage('No active file to scan');
            return;
        }

        await scanFile(editor.document, diagnostics, provider);
    });

    const scanWorkspaceCommand = vscode.commands.registerCommand('byteguardx.scanWorkspace', async () => {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders) {
            vscode.window.showWarningMessage('No workspace folder open');
            return;
        }

        await scanWorkspace(workspaceFolders[0].uri.fsPath, diagnostics, provider);
    });

    const showResultsCommand = vscode.commands.registerCommand('byteguardx.showResults', () => {
        provider.refresh();
        vscode.commands.executeCommand('workbench.view.extension.byteguardx');
    });

    const fixIssueCommand = vscode.commands.registerCommand('byteguardx.fixIssue', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            return;
        }

        await fixProvider.provideFix(editor);
    });

    const openSettingsCommand = vscode.commands.registerCommand('byteguardx.openSettings', () => {
        vscode.commands.executeCommand('workbench.action.openSettings', 'byteguardx');
    });

    // Register auto-scan on save
    const onSaveHandler = vscode.workspace.onDidSaveTextDocument(async (document) => {
        const config = vscode.workspace.getConfiguration('byteguardx');
        if (config.get('autoScan')) {
            await scanFile(document, diagnostics, provider);
        }
    });

    // Register code action provider for fixes
    const codeActionProvider = vscode.languages.registerCodeActionsProvider(
        { scheme: 'file' },
        fixProvider
    );

    // Add to subscriptions
    context.subscriptions.push(
        scanFileCommand,
        scanWorkspaceCommand,
        showResultsCommand,
        fixIssueCommand,
        openSettingsCommand,
        onSaveHandler,
        codeActionProvider
    );

    // Show welcome message
    vscode.window.showInformationMessage('ByteGuardX is ready to scan for security vulnerabilities!');
}

function validateApiUrl(url: string): boolean {
    try {
        const parsed = new URL(url);

        // Only allow HTTP/HTTPS protocols
        if (!['http:', 'https:'].includes(parsed.protocol)) {
            return false;
        }

        // Block dangerous hosts
        const dangerousHosts = ['0.0.0.0', '169.254.169.254', '::1'];
        if (dangerousHosts.includes(parsed.hostname)) {
            return false;
        }

        // Block private IP ranges in production (allow localhost for development)
        const hostname = parsed.hostname;
        if (hostname !== 'localhost' && hostname !== '127.0.0.1') {
            // Block private IP ranges
            const privateRanges = [
                /^10\./,
                /^172\.(1[6-9]|2[0-9]|3[01])\./,
                /^192\.168\./,
                /^fc00:/,
                /^fe80:/
            ];

            for (const range of privateRanges) {
                if (range.test(hostname)) {
                    console.warn(`Blocked private IP range: ${hostname}`);
                    return false;
                }
            }
        }

        return true;
    } catch {
        return false;
    }
}

async function scanFile(document: vscode.TextDocument, diagnostics: SecurityDiagnostics, provider: ByteGuardXProvider) {
    const config = vscode.workspace.getConfiguration('byteguardx');
    const apiUrl = config.get<string>('apiUrl', 'http://localhost:5000');
    const apiKey = config.get<string>('apiKey', '');

    // Validate API URL for security
    if (!validateApiUrl(apiUrl)) {
        vscode.window.showErrorMessage('ByteGuardX: Invalid or insecure API URL');
        return;
    }

    try {
        vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'ByteGuardX: Scanning file...',
            cancellable: false
        }, async (progress) => {
            progress.report({ increment: 0, message: 'Analyzing file content...' });

            const headers: any = {
                'Content-Type': 'application/json'
            };

            if (apiKey) {
                headers['X-API-Key'] = apiKey;
            }

            const response = await axios.post(`${apiUrl}/scan/file`, {
                file_path: document.fileName,
                content: document.getText()
            }, { headers });

            progress.report({ increment: 50, message: 'Processing results...' });

            const result: ScanResult = response.data;
            
            // Update diagnostics
            diagnostics.updateDiagnostics(document.uri, result.findings);
            
            // Update tree view
            provider.updateResults(result);

            progress.report({ increment: 100, message: 'Scan complete!' });

            // Show summary
            const message = `Scan complete: ${result.total_findings} issues found (${result.critical_findings} critical, ${result.high_findings} high)`;
            if (result.critical_findings > 0 || result.high_findings > 0) {
                vscode.window.showWarningMessage(message);
            } else {
                vscode.window.showInformationMessage(message);
            }
        });

    } catch (error: any) {
        console.error('Scan failed:', error);
        
        if (error.response?.status === 401) {
            vscode.window.showErrorMessage('ByteGuardX: Authentication failed. Please check your API key.');
        } else if (error.code === 'ECONNREFUSED') {
            vscode.window.showErrorMessage('ByteGuardX: Cannot connect to API. Please check if the service is running.');
        } else {
            vscode.window.showErrorMessage(`ByteGuardX: Scan failed - ${error.message}`);
        }
    }
}

async function scanWorkspace(workspacePath: string, diagnostics: SecurityDiagnostics, provider: ByteGuardXProvider) {
    const config = vscode.workspace.getConfiguration('byteguardx');
    const apiUrl = config.get<string>('apiUrl', 'http://localhost:5000');
    const apiKey = config.get<string>('apiKey', '');

    try {
        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'ByteGuardX: Scanning workspace...',
            cancellable: false
        }, async (progress) => {
            progress.report({ increment: 0, message: 'Starting workspace scan...' });

            const headers: any = {
                'Content-Type': 'application/json'
            };

            if (apiKey) {
                headers['X-API-Key'] = apiKey;
            }

            const response = await axios.post(`${apiUrl}/scan/directory`, {
                directory_path: workspacePath,
                recursive: true
            }, { headers });

            progress.report({ increment: 30, message: 'Scan submitted, waiting for results...' });

            const scanId = response.data.scan_id;
            
            // Poll for results
            let attempts = 0;
            const maxAttempts = 60; // 5 minutes max
            
            while (attempts < maxAttempts) {
                await new Promise(resolve => setTimeout(resolve, 5000)); // Wait 5 seconds
                
                try {
                    const resultResponse = await axios.get(`${apiUrl}/scan/results/${scanId}`, { headers });
                    const result: ScanResult = resultResponse.data;
                    
                    if (result.status === 'completed') {
                        progress.report({ increment: 70, message: 'Processing results...' });
                        
                        // Update diagnostics for all files
                        const fileFindings: { [key: string]: Finding[] } = {};
                        
                        for (const finding of result.findings) {
                            if (!fileFindings[finding.file_path]) {
                                fileFindings[finding.file_path] = [];
                            }
                            fileFindings[finding.file_path].push(finding);
                        }
                        
                        for (const [filePath, findings] of Object.entries(fileFindings)) {
                            const uri = vscode.Uri.file(filePath);
                            diagnostics.updateDiagnostics(uri, findings);
                        }
                        
                        // Update tree view
                        provider.updateResults(result);
                        
                        progress.report({ increment: 100, message: 'Workspace scan complete!' });
                        
                        // Show summary
                        const message = `Workspace scan complete: ${result.total_findings} issues found across ${Object.keys(fileFindings).length} files`;
                        if (result.critical_findings > 0 || result.high_findings > 0) {
                            vscode.window.showWarningMessage(message);
                        } else {
                            vscode.window.showInformationMessage(message);
                        }
                        
                        return;
                    } else if (result.status === 'failed') {
                        throw new Error('Scan failed on server');
                    }
                    
                    progress.report({ 
                        increment: Math.min(60, attempts * 2), 
                        message: `Scanning... (${result.status})` 
                    });
                    
                } catch (pollError: any) {
                    if (pollError.response?.status !== 404) {
                        throw pollError;
                    }
                }
                
                attempts++;
            }
            
            throw new Error('Scan timeout - please try again');
        });

    } catch (error: any) {
        console.error('Workspace scan failed:', error);
        
        if (error.response?.status === 401) {
            vscode.window.showErrorMessage('ByteGuardX: Authentication failed. Please check your API key.');
        } else if (error.code === 'ECONNREFUSED') {
            vscode.window.showErrorMessage('ByteGuardX: Cannot connect to API. Please check if the service is running.');
        } else {
            vscode.window.showErrorMessage(`ByteGuardX: Workspace scan failed - ${error.message}`);
        }
    }
}

export function deactivate() {
    console.log('ByteGuardX extension deactivated');
}
