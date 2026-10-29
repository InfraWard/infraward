import { Injectable } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { expiryWarningDays } from '@infraward/domain';
import {
  INVENTORY_DEFAULT_EXPORT_COLUMNS,
  INVENTORY_EXPORT_COLUMNS,
  matchesInventoryQuery,
  parseSearchQuery,
  matchesQuickFilter,
  quickFilter,
  type AssetTreeSummaryNode,
  type InventoryExportColumn,
  type Severity,
  priorityReasonText,
} from '@infraward/shared-types';
import { DataSource } from 'typeorm';
import { AssetsService } from '../assets/assets.service.js';
import { toCsv, type CsvValue } from '../common/csv.js';
import { FindingsService } from '../findings/findings.service.js';
import type {
  InventoryExportQueryDto,
  VulnerabilityExportQueryDto,
} from './exports.dto.js';

/** Tope de filas de una exportación de vulnerabilidades. */
export const VULNERABILITY_EXPORT_MAX = 20_000;

const SEVERITIES: readonly Severity[] = [
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'UNKNOWN',
];

export interface ExportFile {
  /** Cuerpo listo para enviar (CSV con BOM o JSON). */
  body: string;
  contentType: string;
  rows: number;
}

type Row = Record<string, CsvValue>;

/**
 * Exportaciones (QoL-6, DESIGN §15): el inventario filtrado como el árbol y las vulnerabilidades
 * con los filtros de la lista. Solo columnas de una lista blanca: nunca conexión, credenciales,
 * referencias a secretos ni facts.
 */
@Injectable()
export class ExportsService {
  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly assets: AssetsService,
    private readonly findings: FindingsService,
  ) {}

  /**
   * Una fila por asset que cumple el filtro (rápido y de texto), en el orden del árbol y con su
   * ruta; los antepasados que el árbol enseña solo para situarlo no entran.
   */
  async inventory(query: InventoryExportQueryDto): Promise<ExportFile> {
    const columns = query.columns?.length
      ? INVENTORY_EXPORT_COLUMNS.filter((c) => query.columns!.includes(c))
      : [...INVENTORY_DEFAULT_EXPORT_COLUMNS];
    const forest = await this.assets.forest(query.includeRetired ?? false);
    const filter = quickFilter(query) ?? {};
    const days = await expiryWarningDays(this.db.manager);
    const projectNames = await this.projectNames();
    const projects = [...projectNames].map(([id, name]) => ({ id, name }));
    const search = parseSearchQuery(query.q ?? '', 'inventory');
    const rows: Row[] = [];
    const walk = (nodes: readonly AssetTreeSummaryNode[], path: string[]) => {
      for (const node of nodes) {
        const here = [...path, node.name];
        if (
          matchesQuickFilter(node, filter, days) &&
          matchesInventoryQuery(node, search, { projects })
        )
          rows.push(inventoryRow(node, here, projectNames));
        walk(node.children, here);
      }
    };
    walk(forest, []);
    return this.file(query.format, columns, rows);
  }

  async vulnerabilities(
    query: VulnerabilityExportQueryDto,
  ): Promise<ExportFile> {
    const filters = { ...query, limit: VULNERABILITY_EXPORT_MAX, offset: 0 };
    if (query.groupBy === 'asset') {
      const projectNames = await this.projectNames();
      const found = await this.findings.vulnerabilitiesByAsset(
        filters,
        VULNERABILITY_EXPORT_MAX,
      );
      if (query.format === 'json')
        return this.json(
          found.map((r) => ({
            id: r.id,
            name: r.name,
            type: r.type,
            projects: names(r.projects, projectNames),
            containers: r.containers,
            cves: r.cves,
            critical: r.critical,
            high: r.high,
            medium: r.medium,
            low: r.low,
            unknown: r.unknown,
            fixable: r.fixable,
            findings: [...r.findings].sort(
              (a, b) =>
                SEVERITIES.indexOf(a.severity as Severity) -
                  SEVERITIES.indexOf(b.severity as Severity) ||
                a.id.localeCompare(b.id),
            ),
          })),
        );
      const rows: Row[] = found.map((r) => ({
        assetId: r.id,
        asset: r.name,
        type: r.type,
        projects: names(r.projects, projectNames),
        containers: r.containers,
        cves: r.cves,
        critical: r.critical,
        high: r.high,
        medium: r.medium,
        low: r.low,
        unknown: r.unknown,
        fixable: r.fixable,
        vulnerabilities: [
          ...new Set(
            [...r.findings]
              .sort(
                (a, b) =>
                  SEVERITIES.indexOf(a.severity as Severity) -
                  SEVERITIES.indexOf(b.severity as Severity),
              )
              .map((f) => f.id),
          ),
        ],
      }));
      return this.file('csv', ASSET_VULN_COLUMNS, rows);
    }
    const page = await this.findings.vulnerabilities(filters);
    const rows: Row[] = page.items.map((v) => ({
      vulnerabilityId: v.vulnerabilityId,
      priority: v.priority?.score ?? null,
      band: v.priority?.band ?? null,
      reasons: v.priority?.reasons.map(priorityReasonText) ?? [],
      severity: v.severity,
      cvss: v.cvss,
      kev: v.kev,
      epss: v.epss,
      title: v.title,
      fixable: v.fixable,
      packages: v.packageNames,
      images: v.images,
      containers: v.containers,
      otherAssets: v.otherAssets,
      unusedImages: v.unusedImages,
      publicDomains: v.exposure?.publicDomains ?? 0,
      url: v.primaryUrl,
    }));
    return this.file(query.format, CVE_COLUMNS, rows);
  }

  private file(
    format: 'csv' | 'json' | undefined,
    columns: readonly string[],
    rows: Row[],
  ): ExportFile {
    if (format === 'json')
      return this.json(
        rows.map((r) =>
          Object.fromEntries(columns.map((c) => [c, r[c] ?? null])),
        ),
      );
    return {
      body: toCsv(columns, rows),
      contentType: 'text/csv; charset=utf-8',
      rows: rows.length,
    };
  }

  private json(rows: unknown[]): ExportFile {
    return {
      body: JSON.stringify(rows, null, 2),
      contentType: 'application/json; charset=utf-8',
      rows: rows.length,
    };
  }

  private async projectNames(): Promise<Map<string, string>> {
    const rows: { id: string; name: string }[] = await this.db.query(
      'SELECT id, name FROM projects',
    );
    return new Map(rows.map((r) => [r.id, r.name]));
  }
}

const CVE_COLUMNS = [
  'vulnerabilityId',
  'priority',
  'band',
  'reasons',
  'severity',
  'cvss',
  'kev',
  'epss',
  'title',
  'fixable',
  'packages',
  'images',
  'containers',
  'otherAssets',
  'unusedImages',
  'publicDomains',
  'url',
];

const ASSET_VULN_COLUMNS = [
  'assetId',
  'asset',
  'type',
  'projects',
  'containers',
  'cves',
  'critical',
  'high',
  'medium',
  'low',
  'unknown',
  'fixable',
  'vulnerabilities',
];

function names(ids: readonly string[], byId: Map<string, string>): string[] {
  return ids.map((id) => byId.get(id)).filter((n): n is string => !!n);
}

function maxSeverity(node: AssetTreeSummaryNode): Severity | null {
  return SEVERITIES.find((s) => node.openFindings[s] > 0) ?? null;
}

/** Solo las columnas de la lista blanca, sacadas del resumen del árbol (que no lleva secretos). */
function inventoryRow(
  node: AssetTreeSummaryNode,
  path: string[],
  projectNames: Map<string, string>,
): Record<InventoryExportColumn, CsvValue> {
  const gone = node.status === 'missing' || node.status === 'retired';
  return {
    id: node.id,
    name: node.name,
    discoveredName: node.discoveredName,
    path: path.join(' › '),
    type: node.type,
    status: node.status,
    runtimeState: gone ? null : node.runtimeState,
    address: node.address,
    roles: node.roles,
    tags: node.tags,
    projects: names(node.projects ?? [], projectNames),
    maxSeverity: maxSeverity(node),
    critical: node.openFindings.CRITICAL,
    high: node.openFindings.HIGH,
    medium: node.openFindings.MEDIUM,
    low: node.openFindings.LOW,
    fixableCritical: node.fixableFindings.CRITICAL,
    fixableHigh: node.fixableFindings.HIGH,
    expiresAt: node.expiresAt,
  };
}
