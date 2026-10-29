# Conexión de InfraWard para recoger un CT de Proxmox SIN SSH dentro del CT (docs/DESIGN.md §8).
#
# Es el plugin `ssh` de ansible-core contra el NODO (misma clave en tmpfs, mismo known_hosts con
# la host key fijada del nodo, mismas opciones) con una diferencia: cada comando se ejecuta
# dentro del CT con la consulta `pct-exec` del ayudante de root del nodo (sudoers v4):
# `sudo -n /usr/local/libexec/infraward/infraward-query pct-exec <vmid> <comando>`, que valida el
# vmid (un CT de este nodo) y ejecuta `pct exec <vmid> -- <comando>`. `pct exec` es root dentro
# del CT: el playbook es de SOLO LECTURA y este plugin no deja copiar ni traer ficheros (con
# `pipelining` los módulos van por stdin).
from __future__ import annotations

import re

from ansible.errors import AnsibleError
from ansible.plugins.connection.ssh import DOCUMENTATION as _SSH_DOCUMENTATION
from ansible.plugins.connection.ssh import Connection as SshConnection

_OPTIONS = "    options:\n"
if _SSH_DOCUMENTATION.count(_OPTIONS) != 1 or "    name: ssh\n" not in _SSH_DOCUMENTATION:
    raise ImportError("infraward_pct: formato inesperado de la documentación del plugin ssh")

# Mismas opciones que `ssh` (se leen igual del inventario y de ansible.cfg) más el vmid.
DOCUMENTATION = _SSH_DOCUMENTATION.replace(
    "    name: ssh\n", "    name: infraward_pct\n", 1
).replace(
    _OPTIONS,
    _OPTIONS
    + """      pct_vmid:
          description: vmid del CT en el que se ejecutan los comandos (con pct exec desde el nodo).
          type: integer
          required: true
          vars:
               - name: infraward_pct_vmid
""",
    1,
)

_VMID = re.compile(r"^[1-9][0-9]{2,8}$")
# Ayudante de root del nodo (INFRAWARD_QUERY_HELPER en packages/connectors/src/privileged.ts).
_HELPER = "/usr/local/libexec/infraward/infraward-query"


class Connection(SshConnection):
    transport = "infraward_pct"

    def _vmid(self) -> str:
        vmid = str(self.get_option("pct_vmid"))
        if not _VMID.match(vmid):
            raise AnsibleError("infraward_pct: vmid no válido")
        return vmid

    def exec_command(self, cmd, in_data=None, sudoable=True):
        # `cmd` ya viene entrecomillado por el shell plugin (`/bin/sh -c '…'`): el shell de
        # login del nodo lo pasa intacto como argumentos de pct exec.
        wrapped = "sudo -n %s pct-exec %s %s" % (_HELPER, self._vmid(), cmd)
        return super().exec_command(wrapped, in_data=in_data, sudoable=sudoable)

    def put_file(self, in_path, out_path):
        raise AnsibleError("infraward_pct: solo lectura, no se copian ficheros al CT")

    def fetch_file(self, in_path, out_path):
        raise AnsibleError("infraward_pct: solo lectura, no se traen ficheros del CT")
