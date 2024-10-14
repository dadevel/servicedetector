# ServiceDetector

Detects named pipes and installed services remotely as unprivileged user.
Heavily based on [tothi/servicedetector](https://github.com/tothi/servicedetector).

![Screenshot](./assets/screenshot.png)

# Setup

a) With [pipx](https://github.com/pypa/pipx).

~~~ bash
pipx install git+https://github.com/dadevel/servicedetector.git@main
~~~

b) With [pip](https://github.com/pypa/pip).

~~~ bash
pip3 install git+https://github.com/dadevel/servicedetector.git@main
~~~

# Usage

Scan computers for WebClient and other NTLM coercion opportunities.

~~~ bash
servicedetector -c coercion -u jdoe -p 'passw0rd' ws01.corp.local ws02.corp.local ws03.corp.local
~~~

Scan computers for installed AV/EDR products.

~~~ bash
servicedetector -c epp -u jdoe -p 'passw0rd' srv01.corp.local srv02.corp.local srv03.corp.local
~~~

You can check for all known software by leaving out the `-c` option.

# About

Running this script connects to the target over SMB and ...

1. performs the [LsarLookupNames()](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsat/65d18faa-0cb2-40ee-a94a-2140212f4ec4) RPC call to check if a given service is installed.
This does not allow to determine if a service is running or stopped.
Furthermore it is not possible to list services.
Only names of known services can be queried.

2. lists named pipes trough the `IPC$` share.
This allows to infer which services are running as long as the respective process creates a named pipe.

3. prints additional info about the target like [NetExec](https://github.com/Pennyw0rth/NetExec/).

# Development

Service names and named pipe paths are defined in [indicators.csv](servicedetector/indicators.csv).
