import { PROXY_LABELS_FORMAT, VOLUME_FORMAT } from '../docker/formats.js';

/**
 * Plantillas de `podman --format` (sudoers v8): el MISMO JSON que las de Docker
 * (`docker/formats.ts`) con los campos de Podman, para que el análisis sea el mismo. Las
 * diferencias, comprobadas con Podman 5.4 (rootful y por el socket de un usuario rootless):
 * - el id es `.ID` (con `.Id` la plantilla falla: «can't evaluate field Id»);
 * - el image ID va sin `sha256:` (`.Image` del contenedor, `.ID` de la imagen): se añade aquí;
 * - los montajes son structs (`.Name` y `.Source` siempre existen; `index` falla con ellos);
 * - las redes son las de netavark: `.Subnets` en vez de `.IPAM.Config`, sin `Scope` (todas son
 *   locales) y la subred con `.String` (con `json` sale como `{IP, Mask}`).
 * Nunca `Config.Env` ni las etiquetas, salvo compose, la lista blanca de Traefik/Caddy y la unidad
 * de systemd que pone Podman (`PODMAN_SYSTEMD_UNIT`, Quadlet o `podman generate systemd`).
 * Un test comprueba que dan las mismas claves que las de Docker.
 */
export const PODMAN_CONTAINER_FORMAT =
  '{"id":{{json .ID}},"name":{{json .Name}},"image":{{json .Config.Image}},' +
  '"imageId":{{json (printf "sha256:%s" .Image)}},"state":{{json .State.Status}},"createdAt":{{json .Created}},' +
  '"startedAt":{{json .State.StartedAt}},"ports":{{json .NetworkSettings.Ports}},' +
  '"bindings":{{json .HostConfig.PortBindings}},' +
  '"composeProject":{{json (index .Config.Labels "com.docker.compose.project")}},' +
  '"composeService":{{json (index .Config.Labels "com.docker.compose.service")}},' +
  PROXY_LABELS_FORMAT +
  '"mounts":[{{range .Mounts}}{"type":{{json .Type}},"name":{{json .Name}},' +
  '"source":{{json .Source}},"destination":{{json .Destination}},"rw":{{json .RW}}},{{end}}null],' +
  '"networks":[{{range $name, $net := .NetworkSettings.Networks}}{"name":{{json $name}},' +
  '"ipv4":{{json $net.IPAddress}},"ipv6":{{json $net.GlobalIPv6Address}},"aliases":{{json $net.Aliases}}},{{end}}null],' +
  // Solo Podman: el pod (su id; el nombre sale de `podman pod ps`), si es el contenedor «infra»
  // del pod (no se inventaría) y la unidad de systemd que lo gestiona.
  '"pod":{{json .Pod}},"infra":{{json .IsInfra}},' +
  '"systemdUnit":{{json (index .Config.Labels "PODMAN_SYSTEMD_UNIT")}}}';
export const PODMAN_IMAGE_FORMAT =
  '{"id":{{json (printf "sha256:%s" .ID)}},"repoDigests":{{json .RepoDigests}},"repoTags":{{json .RepoTags}},' +
  '"os":{{json .Os}},"architecture":{{json .Architecture}},"size":{{json .Size}}}';
/** Volumen: la de Docker vale tal cual. Nunca `Options` ni `Labels`. */
export const PODMAN_VOLUME_FORMAT = VOLUME_FORMAT;
/** Red de netavark: nunca `Options` ni `Labels`. */
export const PODMAN_NETWORK_FORMAT =
  '{"id":{{json .ID}},"name":{{json .Name}},"driver":{{json .Driver}},"scope":"local",' +
  '"internal":{{json .Internal}},"createdAt":{{json .Created}},' +
  '"subnets":[{{range .Subnets}}{"subnet":{{json .Subnet.String}},"gateway":{{json .Gateway}}},{{end}}null]}';
/** Pods: id y nombre (para poner el nombre del pod a sus contenedores). */
export const PODMAN_POD_FORMAT = '{"id":{{json .Id}},"name":{{json .Name}}}';
