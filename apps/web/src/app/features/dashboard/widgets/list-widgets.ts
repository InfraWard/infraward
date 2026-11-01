import { DatePipe, DecimalPipe } from '@angular/common';
import { Component, computed, input } from '@angular/core';
import { RouterLink } from '@angular/router';
import {
  ATTENTION_KIND_LABELS,
  type AttentionData,
  type AttentionKind,
  type DashboardVulnerability,
  type DashboardWidget,
  type ExpirationsData,
  type NewVulnerabilitiesData,
  type RecentActivityData,
  type TopVulnerabilitiesData,
} from '@infraward/shared-types';
import { TagModule } from '@openng/optimus-ui/tag';
import {
  ASSET_TYPE_ICONS,
  formatDuration,
  JOB_ICONS,
  JOB_LABELS,
  JOB_STATE_LABELS,
  JOB_STATE_SEVERITY,
  type TagSeverity,
} from '../../../shared/labels';
import { PriorityReasons, PriorityScore } from '../../../shared/priority';
import { ATTENTION_LINK, type DashboardLinks } from '../dashboard-links';
import { AssetSample } from './counter-widgets';

/** Lista de CVE con su puntuación, severidad, assets y porqué. */
@Component({
  selector: 'app-vulnerability-rows',
  imports: [RouterLink, PriorityReasons, PriorityScore],
  template: `
    <ul class="dw-vulns">
      @for (v of items(); track v.vulnerabilityId) {
        <li [attr.data-top-cve]="v.vulnerabilityId">
          <app-priority-score [priority]="v.priority" [compact]="true" />
          <div class="dw-min">
            <a [routerLink]="['/vulnerabilities', v.vulnerabilityId]"
              ><code>{{ v.vulnerabilityId }}</code></a
            >
            <span class="dw-muted">
              · {{ v.severity }} · {{ v.assets }}
              {{ v.assets === 1 ? 'asset' : 'assets' }}</span
            >
            <app-priority-reasons [reasons]="v.priority.reasons" [max]="3" />
          </div>
        </li>
      }
    </ul>
  `,
})
export class VulnerabilityRows {
  readonly items = input.required<readonly DashboardVulnerability[]>();
}

@Component({
  selector: 'app-top-vulnerabilities-widget',
  imports: [DecimalPipe, RouterLink, VulnerabilityRows],
  template: `
    @if (data().items.length) {
      <app-vulnerability-rows [items]="data().items" />
      <a
        class="dw-more"
        [routerLink]="links().vulnerabilities.path"
        [queryParams]="links().vulnerabilities.queryParams"
      >
        Ver los {{ data().total | number }} en la lista por prioridad
        <i class="bi bi-arrow-right" aria-hidden="true"></i>
      </a>
    } @else {
      <p class="dw-muted">Nada con esta prioridad o más.</p>
    }
  `,
})
export class TopVulnerabilitiesWidget {
  readonly data = input.required<TopVulnerabilitiesData>();
  readonly links = input.required<DashboardLinks>();
}

@Component({
  selector: 'app-new-vulnerabilities-widget',
  imports: [DatePipe, DecimalPipe, RouterLink, VulnerabilityRows],
  template: `
    @let d = data();
    <p class="dw-summary">
      <strong>{{ d.total | number }}</strong>
      {{ d.total === 1 ? 'CVE nuevo' : 'CVE nuevos' }}
      @if (d.kev) {
        ·
        <span class="dw-critical"
          ><i class="bi bi-fire" aria-hidden="true"></i> {{ d.kev }} en
          KEV</span
        >
      }
      <span class="dw-muted"> · desde {{ d.since | date: 'short' }}</span>
    </p>
    @if (d.items.length) {
      <app-vulnerability-rows [items]="d.items" />
      @if (sinceLastVisit()) {
        <a
          class="dw-more"
          [routerLink]="links().newVulnerabilities.path"
          [queryParams]="links().newVulnerabilities.queryParams"
        >
          Ver los nuevos en la lista
          <i class="bi bi-arrow-right" aria-hidden="true"></i>
        </a>
      }
    }
  `,
})
export class NewVulnerabilitiesWidget {
  readonly data = input.required<NewVulnerabilitiesData>();
  readonly links = input.required<DashboardLinks>();
  readonly widget = input.required<DashboardWidget>();
  /** La lista con `?new=1` cuenta desde la última visita; con 7 o 30 días no hay enlace igual. */
  protected readonly sinceLastVisit = computed(
    () => this.widget().options['since'] === 'lastVisit',
  );
}

/** Texto de cada aviso con su número (el mismo que el panel de antes). */
function attentionText(kind: AttentionKind, n: number, days: number): string {
  const one = n === 1;
  switch (kind) {
    case 'duplicates':
      return `${n} ${one ? 'servidor duplicado' : 'servidores duplicados'} (ya en el inventario con otro nombre)`;
    case 'certificatesExpiring':
      return `${n} ${one ? 'certificado caducado o a punto' : 'certificados caducados o a punto'} de caducar (menos de ${days} días)`;
    case 'domainsExpiring':
      return `${n} ${one ? 'dominio caducado o a punto' : 'dominios caducados o a punto'} de caducar (menos de ${days} días)`;
    case 'dnsDangling':
      return `${n} ${one ? 'registro DNS colgante' : 'registros DNS colgantes'} (posible subdomain takeover o destino retirado)`;
    case 'dnsUnknown':
      return `${n} ${one ? 'registro DNS apunta' : 'registros DNS apuntan'} a IPs públicas que no están en el inventario (informativo)`;
    case 'clones':
      return `${n} ${one ? 'servidor clonado' : 'servidores clonados'} con el machine-id sin regenerar`;
    case 'sshCaOutdated':
      return `CA SSH desactualizada en ${n} ${one ? 'servidor' : 'servidores'}`;
    case 'sshdPasswordLogin':
      return `${n} ${one ? 'servidor o CT admite' : 'servidores o CT admiten'} root o contraseñas por SSH`;
    case 'vaultRotationOverdue':
      return `${n} ${one ? 'credencial sin rotar' : 'credenciales sin rotar'} en el plazo (caja fuerte)`;
    case 'sudoersOutdated':
      return `Sudoers desactualizado en ${n} ${one ? 'servidor' : 'servidores'}`;
    case 'partialCollection':
      return `Recolección parcial en ${n} ${one ? 'asset' : 'assets'}`;
    case 'failedJobs':
      return `Tareas fallidas en ${n} ${one ? 'asset' : 'assets'} (24 h)`;
  }
}

const ATTENTION_ICONS: Record<AttentionKind, string> = {
  duplicates: 'bi-files',
  certificatesExpiring: 'bi-patch-exclamation',
  domainsExpiring: 'bi-calendar-x',
  dnsDangling: 'bi-exclamation-octagon',
  dnsUnknown: 'bi-question-circle',
  clones: 'bi-copy',
  sshCaOutdated: 'bi-patch-exclamation',
  sshdPasswordLogin: 'bi-unlock',
  vaultRotationOverdue: 'bi-safe2',
  sudoersOutdated: 'bi-shield-exclamation',
  partialCollection: 'bi-exclamation-triangle',
  failedJobs: 'bi-x-octagon',
};

@Component({
  selector: 'app-attention-widget',
  imports: [RouterLink, AssetSample],
  template: `
    @if (rows().length === 0) {
      <p class="dw-ok">
        <i class="bi bi-check-circle" aria-hidden="true"></i> Nada pendiente.
      </p>
    }
    @for (r of rows(); track r.kind) {
      <div
        class="dw-warning"
        [class.danger]="r.kind === 'dnsDangling'"
        [class.info]="r.kind === 'dnsUnknown'"
        [attr.data-warning]="r.kind"
        [title]="r.label"
      >
        <a
          [routerLink]="r.link.path"
          [queryParams]="r.link.queryParams"
          class="dw-warning-head"
        >
          <i class="bi {{ r.icon }}" aria-hidden="true"></i> {{ r.text }}
        </a>
        @if (r.assets.length) {
          <app-asset-sample [assets]="r.assets" [count]="r.count" />
        }
      </div>
    }
  `,
})
export class AttentionWidget {
  readonly data = input.required<AttentionData>();
  readonly links = input.required<DashboardLinks>();
  protected readonly rows = computed(() => {
    const days = this.data().expiryWarningDays[0] ?? 30;
    const links = this.links();
    return this.data().items.map((item) => ({
      ...item,
      label: ATTENTION_KIND_LABELS[item.kind],
      icon: ATTENTION_ICONS[item.kind],
      text: attentionText(item.kind, item.count, days),
      link: links[ATTENTION_LINK[item.kind]] as {
        path: string;
        queryParams?: Record<string, string>;
      },
    }));
  });
}

@Component({
  selector: 'app-expirations-widget',
  imports: [DatePipe, RouterLink, TagModule],
  template: `
    @let d = data();
    @if (d.items.length) {
      <ul class="dw-rows">
        @for (e of d.items; track e.asset.id) {
          <li [attr.data-expiration]="e.asset.name">
            <i class="bi {{ icons[e.asset.type] }}" aria-hidden="true"></i>
            <a
              class="dw-grow"
              [routerLink]="['/assets', e.asset.id]"
              [title]="e.asset.name"
              >{{ e.asset.name }}</a
            >
            <span class="dw-muted">{{ e.expiresAt | date: 'mediumDate' }}</span>
            <p-tag [value]="left(e.daysLeft)" [severity]="level(e.daysLeft)" />
          </li>
        }
      </ul>
      @if (d.total > d.items.length) {
        <p class="dw-muted">
          y {{ d.total - d.items.length }} más en menos de
          {{ d.horizonDays }} días
        </p>
      }
    } @else {
      <p class="dw-ok">
        <i class="bi bi-check-circle" aria-hidden="true"></i> Nada caduca en
        menos de {{ d.horizonDays }} días.
      </p>
    }
  `,
})
export class ExpirationsWidget {
  readonly data = input.required<ExpirationsData>();
  protected readonly icons: Readonly<Record<string, string>> = ASSET_TYPE_ICONS;

  protected left(days: number): string {
    if (days < 0) return 'Caducado';
    if (days === 0) return 'Hoy';
    return days === 1 ? '1 día' : `${days} días`;
  }

  /** Rojo por debajo del umbral menor (o caducado), ámbar por debajo del mayor. */
  protected level(days: number): TagSeverity {
    const thresholds = this.data().expiryWarningDays;
    const min = Math.min(...thresholds);
    const max = Math.max(...thresholds);
    if (days <= min) return 'danger';
    if (days <= max) return 'warn';
    return 'secondary';
  }
}

@Component({
  selector: 'app-recent-activity-widget',
  imports: [DatePipe, RouterLink, TagModule],
  template: `
    @if (data().items.length) {
      <ul class="dw-rows">
        @for (run of data().items; track run.id) {
          <li [attr.data-run]="run.id">
            <i class="bi {{ jobIcons[run.name] }}" aria-hidden="true"></i>
            <a [routerLink]="['/activity', run.id]" class="dw-run" data-run-link
              ><strong>{{ jobLabels[run.name] }}</strong></a
            >
            @if (run.assetId) {
              <a [routerLink]="['/assets', run.assetId]">{{ run.assetName }}</a>
            } @else {
              <span class="dw-muted">{{ run.assetName ?? '—' }}</span>
            }
            <p-tag
              [value]="stateLabels[run.state]"
              [severity]="stateSeverity[run.state]"
            />
            <span class="dw-when dw-muted"
              >{{ run.createdAt | date: 'short' }} ·
              {{ duration(run.durationMs) }}</span
            >
          </li>
        }
      </ul>
      <a class="dw-more" [routerLink]="links().activity.path"
        >Ver toda la actividad
        <i class="bi bi-arrow-right" aria-hidden="true"></i
      ></a>
    } @else {
      <p class="dw-muted">Aún no hay actividad.</p>
    }
  `,
})
export class RecentActivityWidget {
  readonly data = input.required<RecentActivityData>();
  readonly links = input.required<DashboardLinks>();
  protected readonly jobLabels: Readonly<Record<string, string>> = JOB_LABELS;
  protected readonly jobIcons: Readonly<Record<string, string>> = JOB_ICONS;
  protected readonly stateLabels: Readonly<Record<string, string>> =
    JOB_STATE_LABELS;
  protected readonly stateSeverity: Readonly<Record<string, TagSeverity>> =
    JOB_STATE_SEVERITY;
  protected readonly duration = formatDuration;
}
