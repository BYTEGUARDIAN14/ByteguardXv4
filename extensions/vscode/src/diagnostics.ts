/**
 * ByteGuardX Diagnostics Provider for VS Code
 * Provides inline security issue highlighting
 */

import * as vscode from 'vscode';

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

export class SecurityDiagnostics {
    private diagnosticCollection: vscode.DiagnosticCollection;

    constructor() {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('byteguardx');
    }

    updateDiagnostics(uri: vscode.Uri, findings: Finding[]): void {
        const diagnostics: vscode.Diagnostic[] = [];

        for (const finding of findings) {
            const diagnostic = this.createDiagnostic(finding);
            if (diagnostic) {
                diagnostics.push(diagnostic);
            }
        }

        this.diagnosticCollection.set(uri, diagnostics);
    }

    clearDiagnostics(uri?: vscode.Uri): void {
        if (uri) {
            this.diagnosticCollection.delete(uri);
        } else {
            this.diagnosticCollection.clear();
        }
    }

    private createDiagnostic(finding: Finding): vscode.Diagnostic | null {
        try {
            // Create range for the finding
            const line = Math.max(0, finding.line_number - 1); // Convert to 0-based
            const range = new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER);

            // Create diagnostic
            const diagnostic = new vscode.Diagnostic(
                range,
                `${finding.title}: ${finding.description}`,
                this.getSeverityLevel(finding.severity)
            );

            // Set additional properties
            diagnostic.source = 'ByteGuardX';
            diagnostic.code = {
                value: finding.vulnerability_type,
                target: vscode.Uri.parse(`https://byteguardx.com/docs/vulnerabilities/${finding.vulnerability_type}`)
            };

            // Add related information
            diagnostic.relatedInformation = [
                new vscode.DiagnosticRelatedInformation(
                    new vscode.Location(vscode.Uri.file(finding.file_path), range),
                    `Detected by ${finding.scanner_type} scanner (confidence: ${(finding.confidence_score * 100).toFixed(1)}%)`
                )
            ];

            // Add tags
            const tags: vscode.DiagnosticTag[] = [];
            if (finding.severity === 'low') {
                tags.push(vscode.DiagnosticTag.Unnecessary);
            }
            diagnostic.tags = tags;

            return diagnostic;

        } catch (error) {
            console.error('Error creating diagnostic:', error);
            return null;
        }
    }

    private getSeverityLevel(severity: string): vscode.DiagnosticSeverity {
        switch (severity) {
            case 'critical':
            case 'high':
                return vscode.DiagnosticSeverity.Error;
            case 'medium':
                return vscode.DiagnosticSeverity.Warning;
            case 'low':
                return vscode.DiagnosticSeverity.Information;
            default:
                return vscode.DiagnosticSeverity.Hint;
        }
    }

    dispose(): void {
        this.diagnosticCollection.dispose();
    }
}
