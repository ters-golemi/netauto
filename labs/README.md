# Labs

netlab topologies the **Lab** page builds and audits. Anything here that is a
directory with a `topology.yml`, or a bare `*.yml` file, appears on the page.

This is the `labs_dir` from `config.yaml` (default `labs/`). Point it elsewhere
to keep your topologies out of the repository.

## What's here

- **`spine-leaf/`** — a four-node Arista EOS leaf-spine with an OSPF underlay.
  All native containers, so containerlab brings it up without VM images. This is
  the topology the CI recipe and the README examples use.
- **`mixed-vendor/`** — a small four-vendor network (Juniper, Arista, Cisco
  NX-OS, Cisco IOS) plus a Linux host, to show netauto's platform mapping across
  drivers and the "skipped" state for a node it cannot drive. Heavier to run:
  the Cisco and Juniper kinds are VMs, so it wants the libvirt provider and the
  device images.

## Using it

Either from the Lab page (Bring up → Audit this lab → Tear down), or by hand:

```bash
cd labs/spine-leaf && netlab up          # build it
python -m netauto.lab.ci labs/spine-leaf/topology.yml --fail-on high   # audit as a gate
cd labs/spine-leaf && netlab down --cleanup   # tear it down
```

netlab is optional and not a netauto dependency — install it and a provider
(containerlab or libvirt) separately. Lab devices share the `LAB` credential
prefix, so export `LAB_USERNAME` and `LAB_PASSWORD` before auditing. See
[../docs/netlab-integration.md](../docs/netlab-integration.md).

## What is not committed

Bringing a lab up writes generated files beside its topology — the snapshot, the
containerlab config, Ansible `host_vars` / `group_vars`. These are ignored by
git (see the repository `.gitignore`); only the topologies and this README are
tracked.
