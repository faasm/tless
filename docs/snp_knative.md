# SNP-Knative

TODO(docs): explain SNP-Knative design

## Deploy

We deploy SNP-Knative on child-capable VMs on Azure. These are VMs that support
creating confidential child VMs. The child VMs are, at all effects,
regular SNP guests.

To deploy SNP-Knative, just run:

```bash
invrs azure snp-knative create
# The provisioning step, particularly deploying the SC2 cluster, can take 10-15'
invrs azure snp-knative provision
```

### Notes

The QEMU/OVMF version for Azure CC VMs is based on CoCo 0.12.0, so we need to
revert some of the changes we did when moving to 0.13.0. As far as I can tell,
the only thing needed is to undo the `-bios` option:

```diff
diff --git a/src/runtime/pkg/govmm/qemu/qemu.go b/src/runtime/pkg/govmm/qemu/qemu.go
index aefa1ffdf..448d2264c 100644
--- a/src/runtime/pkg/govmm/qemu/qemu.go
+++ b/src/runtime/pkg/govmm/qemu/qemu.go
@@ -387,7 +387,11 @@ func (object Object) QemuParams(config *Config) []string {
                objectParams = append(objectParams, fmt.Sprintf("cbitpos=%d", object.CBitPos))
                objectParams = append(objectParams, fmt.Sprintf("reduced-phys-bits=%d", object.ReducedPhysBits))
                objectParams = append(objectParams, "kernel-hashes=on")
-               config.Bios = object.File
+               // We may need this for azure
+               driveParams = append(driveParams, "if=pflash,format=raw,readonly=on")
+               driveParams = append(driveParams, fmt.Sprintf("file=%s", object.File))
        case SecExecGuest:
                objectParams = append(objectParams, string(object.Type))
                objectParams = append(objectParams, fmt.Sprintf("id=%s", object.ID))
```

we also need to re-build our `nydus-image` binary, as it links with the wrong
GLIBC version. This is because the gallery image we use is based on 22.04.
We can follow the instructions in `sc2-sys/deploy/docker/nydus.dockerfile`.
