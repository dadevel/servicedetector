# ServiceDetector

Detects named pipes and installed services remotely as unprivileged user.
Heavily based on [tothi/servicedetector](https://github.com/tothi/servicedetector).

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

Scan multiple servers for installed AV/EDR products.
Service names and named pipes are defined in JSON files in the [./conf](./conf) directory.

~~~ bash
servicedetector -c ./conf/edr.json -u jdoe -p 'passw0rd' srv01.corp.local srv02.corp.local srv03.corp.local
~~~

# About

In more detail, running this script connects to the target over SMB and checks:

1. if the specified services are installed through the [LsarLookupNames()](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsat/65d18faa-0cb2-40ee-a94a-2140212f4ec4) RPC call.
It is not possible to detect if the service is running or stopped.
Furthermore it is not possible to list services.
Only names of known services can be queried.

2. which Named Pipes exist on the target.
This allows to infer which processes / services are running.
