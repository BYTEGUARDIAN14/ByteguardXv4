/**
 * ByteGuardX Tree Data Provider for VS Code
 */

import * as vscode from 'vscode';
import * as path from 'path';

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

export class ByteGuardXProvider implements vscode.TreeDataProvider<TreeItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<TreeItem | undefined | null | void> = new vscode.EventEmitter<TreeItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<TreeItem | undefined | null | void> = this._onDidChangeTreeData.event;

    private scanResults: ScanResult | null = null;

    constructor(private context: vscode.ExtensionContext) {}

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    updateResults(results: ScanResult): void {
        this.scanResults = results;
        this.refresh();
        
        // Set context for when results are available
        vscode.commands.executeCommand('setContext', 'byteguardx.hasResults', true);
    }

    getTreeItem(element: TreeItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: TreeItem): Thenable<TreeItem[]> {
        if (!this.scanResults) {
            return Promise.resolve([]);
        }

        if (!element) {
            // Root level - show summary and severity groups
            const items: TreeItem[] = [];
            
            // Summary item
            items.push(new SummaryItem(this.scanResults));
            
            // Severity groups
            const severities = ['critical', 'high', 'medium', 'low'] as const;
            for (const severity of severities) {
                const findings = this.scanResults.findings.filter(f => f.severity === severity);
                if (findings.length > 0) {
                    items.push(new SeverityGroupItem(severity, findings));
                }
            }
            
            return Promise.resolve(items);
        }

        if (element instanceof SeverityGroupItem) {
            // Show findings for this severity
            return Promise.resolve(element.findings.map(f => new FindingItem(f)));
        }

        return Promise.resolve([]);
    }
}

abstract class TreeItem extends vscode.TreeItem {
    constructor(
        public readonly label: string,
        public readonly collapsibleState: vscode.TreeItemCollapsibleState
    ) {
        super(label, collapsibleState);
    }
}

class SummaryItem extends TreeItem {
    constructor(private scanResult: ScanResult) {
        super(
            `Scan Results: ${scanResult.total_findings} issues found`,
            vscode.TreeItemCollapsibleState.None
        );
        
        this.description = `${scanResult.critical_findings}C ${scanResult.high_findings}H ${scanResult.medium_findings}M ${scanResult.low_findings}L`;
        this.iconPath = new vscode.ThemeIcon('info');
        this.contextValue = 'summary';
    }
}

class SeverityGroupItem extends TreeItem {
    constructor(
        public readonly severity: 'critical' | 'high' | 'medium' | 'low',
        public readonly findings: Finding[]
    ) {
        super(
            `${severity.toUpperCase()} (${findings.length})`,
            vscode.TreeItemCollapsibleState.Expanded
        );
        
        this.iconPath = SeverityGroupItem.getIconForSeverity(severity);
        this.contextValue = 'severityGroup';
    }

    private static getIconForSeverity(severity: string): vscode.ThemeIcon {
        switch (severity) {
            case 'critical':
                return new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
            case 'high':
                return new vscode.ThemeIcon('warning', new vscode.ThemeColor('problemsWarningIcon.foreground'));
            case 'medium':
                return new vscode.ThemeIcon('info', new vscode.ThemeColor('problemsInfoIcon.foreground'));
            case 'low':
                return new vscode.ThemeIcon('circle-outline');
            default:
                return new vscode.ThemeIcon('circle-outline');
        }
    }
}

class FindingItem extends TreeItem {
    constructor(public readonly finding: Finding) {
        super(
            finding.title,
            vscode.TreeItemCollapsibleState.None
        );
        
        this.description = `${path.basename(finding.file_path)}:${finding.line_number}`;
        this.tooltip = new vscode.MarkdownString(
            `**${finding.title}**\n\n` +
            `${finding.description}\n\n` +
            `**File:** ${finding.file_path}\n` +
            `**Line:** ${finding.line_number}\n` +
            `**Type:** ${finding.vulnerability_type}\n` +
            `**Scanner:** ${finding.scanner_type}\n` +
            `**Confidence:** ${(finding.confidence_score * 100).toFixed(1)}%`
        );
        
        this.iconPath = FindingItem.getIconForSeverity(finding.severity);
        this.contextValue = 'finding';
        
        // Command to open file at specific line
        this.command = {
            command: 'vscode.open',
            title: 'Open File',
            arguments: [
                vscode.Uri.file(finding.file_path),
                {
                    selection: new vscode.Range(
                        finding.line_number - 1, 0,
                        finding.line_number - 1, 0
                    )
                }
            ]
        };
    }

    private static getIconForSeverity(severity: string): vscode.ThemeIcon {
        switch (severity) {
            case 'critical':
                return new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
            case 'high':
                return new vscode.ThemeIcon('warning', new vscode.ThemeColor('problemsWarningIcon.foreground'));
            case 'medium':
                return new vscode.ThemeIcon('info', new vscode.ThemeColor('problemsInfoIcon.foreground'));
            case 'low':
                return new vscode.ThemeIcon('circle-outline');
            default:
                return new vscode.ThemeIcon('circle-outline');
        }
    }
}
