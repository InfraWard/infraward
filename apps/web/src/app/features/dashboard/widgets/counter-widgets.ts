import { DecimalPipe } from '@angular/common';
import { Component, computed, input } from '@angular/core';
import { RouterLink } from '@angular/router';
import type {
  AssetCountsData,
  FixableVulnerabilitiesData,
  ProjectStats,
  AssetSummary,
  PendingEnrollmentData,
  RunningJobsData,
  VulnerabilityCountsData,
} from '@infraward/shared-types';
import { ASSET_TYPE_ICONS } from '../../../shared/labels';
import { fixableLabel } from '../../projects/project-stats';
import { AssetTypeChips, SeverityBar } from '../../projects/project-visuals';
import { countTiles, type DashboardLinks } from '../dashboard-links';

/** CVE prioritarios de la vista principal: urgentes + altos, con KEV y el total ≥ media. */
@Component({
  selector: 'app-vulnerability-counts-widget',
  imports: [DecimalPipe, RouterLink],
  template: `
    @let d = data();
    <a
      class="dw-tile"
      [routerLink]="links().vulnerabilities.path"
      [queryParams]="links().vulnerabilities.queryParams"
    >
      <span class="dw-value">{{ d.urgent + d.high | number }}</span>
      <span class="dw-detail">
        <span
          ><i
            class="bi bi-exclamation-octagon-fill dw-critical"
            aria-hidden="true"
          ></i>
          {{ d.urgent | number }}
          {{ d.urgent === 1 ? 'urgente' : 'urgentes' }}</span
        >
        <span
          ><i
            class="bi bi-exclamation-triangle-fill dw-high"
            aria-hidden="true"
          ></i>
          {{ d.high | number }} {{ d.high === 1 ? 'alta' : 'altas' }}</span
        >
        @if (d.kev) {
          <span
            ><i class="bi bi-fire dw-critical" aria-hidden="true"></i>
            {{ d.kev | number }} en KEV</span
          >
        }
      </span>
      <span class="dw-muted"
        >{{ d.cves | number }} CVE con prioridad media o más</span
      >
    </a>
  `,
})
export class VulnerabilityCountsWidget {
  readonly data = input.required<VulnerabilityCountsData>();
  readonly links = input.required<DashboardLinks>();
}

/** Assets por tipo o por estado, cada uno enlazado al inventario filtrado. */
@Component({
  selector: 'app-asset-counts-widget',
  imports: [DecimalPipe, RouterLink],
  template: `
    @if (tiles().length) {
      <ul class="dw-counts">
        @for (t of tiles(); track t.key) {
          <li>
            @if (t.link; as link) {
              <a
                [routerLink]="link.path"
                [queryParams]="link.queryParams"
                [attr.data-count]="t.key"
              >
                <i class="bi {{ t.icon }}" aria-hidden="true"></i
                ><span>{{ t.label }}</span
                ><strong>{{ t.count | number }}</strong>
              </a>
            } @else {
              <span class="dw-static" [attr.data-count]="t.key">
                <i class="bi {{ t.icon }}" aria-hidden="true"></i
                ><span>{{ t.label }}</span
                ><strong>{{ t.count | number }}</strong>
              </span>
            }
          </li>
        }
      </ul>
    } @else {
      <p class="dw-muted">
        No hay assets con estos filtros.
        <a routerLink="/enroll">Añade un servidor</a>.
      </p>
    }
  `,
})
export class AssetCountsWidget {
  readonly data = input.required<AssetCountsData>();
  readonly links = input.required<DashboardLinks>();
  protected readonly tiles = computed(() =>
    countTiles(this.data().groupBy, this.data().counts, this.links()),
  );
}

/** Lista corta de assets (los primeros de un aviso o de los pendientes) con «y N más». */
@Component({
  selector: 'app-asset-sample',
  imports: [RouterLink],
  template: `
    <ul class="dw-sample">
      @for (a of assets(); track a.id) {
        <li>
          <a [routerLink]="['/assets', a.id]"
            ><i class="bi {{ icons[a.type] }}" aria-hidden="true"></i>
            {{ a.name }}</a
          >
        </li>
      }
      @if (count() > assets().length) {
        <li class="dw-muted">y {{ count() - assets().length }} más</li>
      }
    </ul>
  `,
})
export class AssetSample {
  readonly assets = input.required<readonly AssetSummary[]>();
  readonly count = input.required<number>();
  protected readonly icons: Readonly<Record<string, string>> = ASSET_TYPE_ICONS;
}

@Component({
  selector: 'app-pending-enrollment-widget',
  imports: [DecimalPipe, RouterLink, AssetSample],
  template: `
    @let d = data();
    <a
      class="dw-tile"
      [routerLink]="links().pending.path"
      [queryParams]="links().pending.queryParams"
    >
      <span class="dw-value">{{ d.count | number }}</span>
      <span class="dw-muted">{{
        d.count
          ? 'Servidores esperando al script de alta'
          : 'Ningún servidor pendiente'
      }}</span>
    </a>
    @if (d.assets.length) {
      <app-asset-sample [assets]="d.assets" [count]="d.count" />
    }
  `,
})
export class PendingEnrollmentWidget {
  readonly data = input.required<PendingEnrollmentData>();
  readonly links = input.required<DashboardLinks>();
}

@Component({
  selector: 'app-running-jobs-widget',
  imports: [DecimalPipe, RouterLink],
  template: `
    @let d = data();
    <a
      class="dw-tile"
      [routerLink]="links().running.path"
      [queryParams]="links().running.queryParams"
    >
      <span class="dw-value">{{ d.count | number }}</span>
      <span class="dw-muted">{{
        d.count
          ? 'Recolecciones, descubrimientos o escaneos'
          : 'El worker está en reposo'
      }}</span>
    </a>
  `,
})
export class RunningJobsWidget {
  readonly data = input.required<RunningJobsData>();
  readonly links = input.required<DashboardLinks>();
}

/** Lo que piden la barra de severidad y los chips de tipos (las mismas piezas que la tarjeta). */
function asStats(
  partial: Partial<ProjectStats> & Pick<ProjectStats, 'assets'>,
): ProjectStats {
  return {
    assetsByType: {},
    openFindings: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 },
    fixableFindings: { CRITICAL: 0, HIGH: 0 },
    openVulnerabilities: 0,
    ...partial,
  };
}

/** Total de assets y un chip por tipo → inventario filtrado. */
@Component({
  selector: 'app-asset-summary-widget',
  imports: [DecimalPipe, RouterLink, AssetTypeChips],
  template: `
    <a
      class="dw-tile"
      [routerLink]="links().inventory.path"
      [queryParams]="links().inventory.queryParams"
    >
      <span class="dw-value">{{ data().total | number }}</span>
      @if (data().total) {
        <app-asset-type-chips [stats]="stats()" />
      } @else {
        <span class="dw-muted">Ninguno todavía</span>
      }
    </a>
  `,
})
export class AssetSummaryWidget {
  readonly data = input.required<AssetCountsData>();
  readonly links = input.required<DashboardLinks>();
  protected readonly stats = computed(() =>
    asStats({ assets: this.data().total, assetsByType: this.data().counts }),
  );
}

/** Críticos + altos con parche, «2 C · 5 H», CVE abiertos y la barra por severidad. */
@Component({
  selector: 'app-fixable-vulnerabilities-widget',
  imports: [DecimalPipe, RouterLink, SeverityBar],
  template: `
    @let d = data();
    <a
      class="dw-tile"
      [routerLink]="links().vulnerabilities.path"
      [queryParams]="links().vulnerabilities.queryParams"
    >
      <span class="dw-value">{{
        d.fixableFindings.CRITICAL + d.fixableFindings.HIGH | number
      }}</span>
      <span class="dw-muted"
        >{{ label() ?? 'Ninguna C/H con parche' }} ·
        {{ d.openVulnerabilities | number }} CVE abiertos</span
      >
      @if (d.openVulnerabilities) {
        <app-severity-bar [stats]="stats()" />
      }
    </a>
  `,
})
export class FixableVulnerabilitiesWidget {
  readonly data = input.required<FixableVulnerabilitiesData>();
  readonly links = input.required<DashboardLinks>();
  protected readonly stats = computed(() =>
    asStats({ assets: 0, ...this.data() }),
  );
  protected readonly label = computed(() => fixableLabel(this.stats()));
}
