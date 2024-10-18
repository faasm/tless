## Deploy on Knative

To deploy the Knative-based baselines - Knative, CC-Knative, and TLess-Knative -
run the following:

```bash
# TODO
```

### Notes on Knative

We need to edit the InMemoryChannel dispatcher

```
kubectl edit configmap config-imc-event-dispatcher -n knative-eventing

deliveryTimeout: "30s"
dispatcherConcurrency: 10
```

or alternatively try not to send many messages at once to the same InMemoryChannel.
In the future we should move to Kafka.

### CoCo Troubleshooting

#### Error Canonicalizing

CoCo version `0.9.0` ships with a bug where we cannot unpack layers with
very long file names, as they get clipped to 100 characters.

You would see an error message like the following one (notice that the last
file name is clipped):

```txt
No such file or directory (os error 2) while canonicalizing /run/kata-containers/image/layers/sha256_d25f740b6a40d5ed8e32dc0cb536bc333c78add61ebd9c0335b77d2fd0bce256/code/faasm-examples/workflows/finra/knative/target/release/build/rustls-23cc6530a2458bd3/build-scrip
```
#### CrashLoop Taking Too Long

```bash
sudo vi /var/lib/kubelet.config

# add the folllowing
containerRuntimeBackOff: "5s"
containerRuntimeMaxBackOff: "5s"
```

