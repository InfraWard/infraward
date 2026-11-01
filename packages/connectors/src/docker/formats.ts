/**
 * Plantillas de `--format`: solo salen del servidor los campos necesarios. Nunca `Config.Env`
 * (variables de entorno con secretos) ni las etiquetas (salvo el proyecto y el servicio de
 * compose y la lista blanca de Traefik/Caddy). Las de Podman (`podman/formats.ts`) dan el mismo
 * JSON con los campos de Podman.
 */

/**
 * Etiquetas de Traefik y Caddy (QoL-5b), compartidas con las plantillas de Podman: SOLO las
 * claves de esta lista blanca salen del servidor, como pares [clave, valor]: traefik.enable,
 * traefik.docker.network, traefik.http.routers.<n>.rule|service,
 * traefik.http.services.<n>.loadbalancer.server.port, caddy[_N] y caddy[_N].reverse_proxy. Ni
 * middlewares (basicauth), ni el resto.
 */
export const PROXY_LABELS_FORMAT =
  '"proxyLabels":[{{range $k, $v := .Config.Labels}}{{$p := split $k "."}}{{$n := len $p}}{{$h := index $p 0}}' +
  '{{if or (eq $k "traefik.enable") (eq $k "traefik.docker.network")}}[{{json $k}},{{json $v}}],' +
  '{{else if eq $h "traefik"}}{{if eq $n 5}}{{if and (eq (index $p 1) "http") (eq (index $p 2) "routers")}}' +
  '{{if or (eq (index $p 4) "rule") (eq (index $p 4) "service")}}[{{json $k}},{{json $v}}],{{end}}{{end}}' +
  '{{else if eq $n 7}}{{if and (eq (index $p 1) "http") (eq (index $p 2) "services") (eq (index $p 4) "loadbalancer") (eq (index $p 5) "server") (eq (index $p 6) "port")}}' +
  '[{{json $k}},{{json $v}}],{{end}}{{end}}' +
  '{{else if eq (index (split $h "_") 0) "caddy"}}{{if eq $n 1}}[{{json $k}},{{json $v}}],' +
  '{{else if and (eq $n 2) (eq (index $p 1) "reverse_proxy")}}[{{json $k}},{{json $v}}],{{end}}{{end}}{{end}}null],';

export const CONTAINER_FORMAT =
  '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Config.Image}},' +
  '"imageId":{{json .Image}},"state":{{json .State.Status}},"createdAt":{{json .Created}},' +
  '"startedAt":{{json .State.StartedAt}},"ports":{{json .NetworkSettings.Ports}},' +
  '"bindings":{{json .HostConfig.PortBindings}},' +
  '"composeProject":{{json (index .Config.Labels "com.docker.compose.project")}},' +
  '"composeService":{{json (index .Config.Labels "com.docker.compose.service")}},' +
  PROXY_LABELS_FORMAT +
  // Montajes y redes campo a campo (sin opciones del driver); la lista acaba en `null`. Un bind
  // no tiene `Name`: las claves opcionales van con `index` (null si faltan; con `.Name` la
  // plantilla falla: «map has no entry for key»).
  '"mounts":[{{range .Mounts}}{"type":{{json .Type}},"name":{{json (index . "Name")}},' +
  '"source":{{json (index . "Source")}},"destination":{{json .Destination}},"rw":{{json .RW}}},{{end}}null],' +
  '"networks":[{{range $name, $net := .NetworkSettings.Networks}}{"name":{{json $name}},' +
  '"ipv4":{{json $net.IPAddress}},"ipv6":{{json $net.GlobalIPv6Address}},"aliases":{{json $net.Aliases}}},{{end}}null]}';
export const IMAGE_FORMAT =
  '{"id":{{json .Id}},"repoDigests":{{json .RepoDigests}},"repoTags":{{json .RepoTags}},' +
  '"os":{{json .Os}},"architecture":{{json .Architecture}},"size":{{json .Size}}}';
/** Volumen: nunca `Options` (credenciales de NFS/CIFS) ni `Labels`. */
export const VOLUME_FORMAT =
  '{"name":{{json .Name}},"driver":{{json .Driver}},"scope":{{json .Scope}},' +
  '"mountpoint":{{json .Mountpoint}},"createdAt":{{json .CreatedAt}}}';
/** Red: nunca `Options` ni `Labels`. */
export const NETWORK_FORMAT =
  '{"id":{{json .Id}},"name":{{json .Name}},"driver":{{json .Driver}},"scope":{{json .Scope}},' +
  '"internal":{{json .Internal}},"createdAt":{{json .Created}},' +
  '"subnets":[{{range .IPAM.Config}}{"subnet":{{json .Subnet}},"gateway":{{json .Gateway}}},{{end}}null]}';
