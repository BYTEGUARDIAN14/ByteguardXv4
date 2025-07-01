/**
 * ByteGuardX Fix Provider for VS Code
 * Provides AI-powered security fix suggestions
 */

import * as vscode from 'vscode';
import axios from 'axios';

interface FixSuggestion {
    suggestion_id: string;
    finding_id: string;
    fix_type: string;
    description: string;
    code_changes: Array<{
        line_number: number;
        original_code: string;
        fixed_code: string;
        action: 'replace' | 'insert' | 'delete';
    }>;
    confidence_score: number;
    estimated_effort: string;
}

export class FixProvider implements vscode.CodeActionProvider {
    
    async provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
        token: vscode.CancellationToken
    ): Promise<vscode.CodeAction[]> {
        const actions: vscode.CodeAction[] = [];

        // Check if there are ByteGuardX diagnostics in the range
        const byteguardxDiagnostics = context.diagnostics.filter(
            diagnostic => diagnostic.source === 'ByteGuardX'
        );

        if (byteguardxDiagnostics.length === 0) {
            return actions;
        }

        // Create fix actions for each diagnostic
        for (const diagnostic of byteguardxDiagnostics) {
            const fixAction = new vscode.CodeAction(
                `🛡️ Fix security issue: ${diagnostic.message}`,
                vscode.CodeActionKind.QuickFix
            );

            fixAction.command = {
                command: 'byteguardx.applyFix',
                title: 'Apply ByteGuardX Fix',
                arguments: [document, diagnostic, range]
            };

            fixAction.diagnostics = [diagnostic];
            fixAction.isPreferred = diagnostic.severity === vscode.DiagnosticSeverity.Error;

            actions.push(fixAction);
        }

        return actions;
    }

    async provideFix(editor: vscode.TextEditor): Promise<void> {
        const config = vscode.workspace.getConfiguration('byteguardx');
        const apiUrl = config.get<string>('apiUrl', 'http://localhost:5000');
        const apiKey = config.get<string>('apiKey', '');

        try {
            // Get current line
            const position = editor.selection.active;
            const line = position.line + 1; // Convert to 1-based

            // Find finding ID for this line (simplified - in real implementation would track findings)
            const findingId = `temp_finding_${Date.now()}`;

            await vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: 'ByteGuardX: Getting fix suggestions...',
                cancellable: false
            }, async (progress) => {
                progress.report({ increment: 0, message: 'Analyzing security issue...' });

                const headers: any = {
                    'Content-Type': 'application/json'
                };

                if (apiKey) {
                    headers['X-API-Key'] = apiKey;
                }

                // Get fix suggestions
                const response = await axios.get(`${apiUrl}/fix/suggestions/${findingId}`, { headers });
                const suggestions: FixSuggestion[] = response.data.suggestions || [];

                progress.report({ increment: 50, message: 'Processing suggestions...' });

                if (suggestions.length === 0) {
                    vscode.window.showInformationMessage('No fix suggestions available for this issue.');
                    return;
                }

                // Show suggestions to user
                const items = suggestions.map(suggestion => ({
                    label: `${suggestion.fix_type}: ${suggestion.description}`,
                    description: `Confidence: ${(suggestion.confidence_score * 100).toFixed(1)}% | Effort: ${suggestion.estimated_effort}`,
                    suggestion
                }));

                const selected = await vscode.window.showQuickPick(items, {
                    placeHolder: 'Select a fix to apply',
                    ignoreFocusOut: true
                });

                if (!selected) {
                    return;
                }

                progress.report({ increment: 80, message: 'Applying fix...' });

                // Apply the selected fix
                await this.applyFixSuggestion(editor, selected.suggestion);

                progress.report({ increment: 100, message: 'Fix applied!' });

                vscode.window.showInformationMessage('Security fix applied successfully!');
            });

        } catch (error: any) {
            console.error('Fix failed:', error);
            
            if (error.response?.status === 404) {
                vscode.window.showWarningMessage('No fix suggestions found for this security issue.');
            } else if (error.response?.status === 401) {
                vscode.window.showErrorMessage('ByteGuardX: Authentication failed. Please check your API key.');
            } else if (error.code === 'ECONNREFUSED') {
                vscode.window.showErrorMessage('ByteGuardX: Cannot connect to API. Please check if the service is running.');
            } else {
                vscode.window.showErrorMessage(`ByteGuardX: Fix failed - ${error.message}`);
            }
        }
    }

    private async applyFixSuggestion(editor: vscode.TextEditor, suggestion: FixSuggestion): Promise<void> {
        const document = editor.document;
        const edit = new vscode.WorkspaceEdit();

        // Validate all changes before applying
        for (const change of suggestion.code_changes) {
            if (!this.validateCodeChange(change)) {
                throw new Error(`Invalid code change detected: ${change.action}`);
            }
        }

        // Sort changes by line number (descending) to avoid offset issues
        const sortedChanges = suggestion.code_changes.sort((a, b) => b.line_number - a.line_number);

        for (const change of sortedChanges) {
            const lineIndex = change.line_number - 1; // Convert to 0-based
            
            if (lineIndex < 0 || lineIndex >= document.lineCount) {
                continue;
            }

            const line = document.lineAt(lineIndex);
            
            switch (change.action) {
                case 'replace':
                    edit.replace(document.uri, line.range, change.fixed_code);
                    break;
                    
                case 'insert':
                    edit.insert(document.uri, line.range.end, '\n' + change.fixed_code);
                    break;
                    
                case 'delete':
                    edit.delete(document.uri, line.rangeIncludingLineBreak);
                    break;
            }
        }

        // Apply the edit
        const success = await vscode.workspace.applyEdit(edit);
        
        if (!success) {
            throw new Error('Failed to apply code changes');
        }

        // Format the document if auto-format is enabled
        const config = vscode.workspace.getConfiguration('editor');
        if (config.get('formatOnSave')) {
            await vscode.commands.executeCommand('editor.action.formatDocument');
        }
    }

    private validateCodeChange(change: any): boolean {
        // Validate action type
        const allowedActions = ['replace', 'insert', 'delete'];
        if (!allowedActions.includes(change.action)) {
            return false;
        }

        // Validate line number
        if (typeof change.line_number !== 'number' || change.line_number < 1) {
            return false;
        }

        // Validate fixed_code for replace and insert actions
        if ((change.action === 'replace' || change.action === 'insert') && change.fixed_code) {
            // Check for potentially malicious code patterns
            const dangerousPatterns = [
                /eval\s*\(/,
                /Function\s*\(/,
                /setTimeout\s*\(/,
                /setInterval\s*\(/,
                /document\.write/,
                /innerHTML\s*=/,
                /outerHTML\s*=/,
                /javascript:/,
                /<script/i,
                /on\w+\s*=/i, // event handlers like onclick=
                /import\s+.*from\s+['"]http/,
                /require\s*\(\s*['"]http/,
                /fetch\s*\(/,
                /XMLHttpRequest/,
                /\.exec\s*\(/,
                /child_process/,
                /fs\./,
                /process\./
            ];

            for (const pattern of dangerousPatterns) {
                if (pattern.test(change.fixed_code)) {
                    console.warn(`Dangerous pattern detected in code change: ${pattern}`);
                    return false;
                }
            }

            // Check for excessively long code (potential DoS)
            if (change.fixed_code.length > 10000) {
                console.warn('Code change too long, potential DoS attempt');
                return false;
            }
        }

        return true;
    }
}

// Register the apply fix command
vscode.commands.registerCommand('byteguardx.applyFix', async (
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic,
    range: vscode.Range
) => {
    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.document !== document) {
        return;
    }

    const fixProvider = new FixProvider();
    await fixProvider.provideFix(editor);
});
