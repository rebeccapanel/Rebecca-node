# Rebecca-node

## Quick install
Install Rebecca-node on your server using this command
```bash
sudo bash -c "$(curl -sL https://github.com/rebeccapanel/Rebecca-scripts/raw/master/rebecca-node.sh)" @ install
```
Install Rebecca-node on your server using this command with custom name:
```bash
sudo bash -c "$(curl -sL https://github.com/rebeccapanel/Rebecca-scripts/raw/master/rebecca-node.sh)" @ install --name rebecca-node2
```
Or you can only install this script (Rebecca-node command) on your server by using this command
```bash
sudo bash -c "$(curl -sL https://github.com/rebeccapanel/Rebecca-scripts/raw/master/rebecca-node.sh)" @ install-script
```

Use `help` to view all commands:
```Rebecca-node help```


## Manual install
Read the setup guide here: Soon!

## Runtime
Rebecca-node is implemented in Go and ships two binaries:

- `rebecca-node`: the TLS REST API used by the Rebecca master to control Xray
- `rebecca-node-service`: the local maintenance API used for node update/restart commands

## Binary builds
Linux `amd64` binaries are built for:

- every push to `dev`
- every pull request
- every published or prereleased GitHub release

Release assets are uploaded as raw executables:

- `rebecca-node-<version>-linux-amd64`
- `rebecca-node-service-<version>-linux-amd64`

You can also reproduce the CI packaging flow locally:

```bash
go run ./tools/build
go run ./tools/smoke
```

The Go packages can be checked directly with:

```bash
go test ./...
```
