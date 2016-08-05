# Holmes-Gateway
Main program for receiving tasking and objects. It validates input, checks authentication, and pushes the requests to the pipeline.

# USAGE
## Setup
### Starting Master-Gateway
If you don't have an SSL-Certificate, create one by executing "mkcert.sh"

Copy the file config-master.json.example to config-master.json and edit it to suit your needs.
The following configuration options are available:
* **HTTP**: The binding for the http-listener
* **SourcesKeysPath**: The path to where the public keys of the sources are found. The keys must be in PEM-format and must have the file-extension \*.pub
* **TicketSignKeyPath**: Path to the private key which is used for signing tickets
* **Organizations**: The list of all known slave-gateways. In the future, this may move to be dynamically configurable from Holmes-Storage. For each Organization a Name, the URI, and the list of sources must be given.
* **OwnOrganization**: The name of the own organization. An organization with this name must also be present in the list of organizations. This organization is used for automatic tasking.
* **AllowedUsers**: A dict mapping the usernames of allowed users to their bcrypt-password-hash. In the future, the credentials will be stored in Holmes-Storage instead
* **StorageURI**: The URI to where storage resides for uploading samples
* **AutoTasks**: A dict for tasks, that should be executed automatically whenever a sample is uploaded.
* **CertificateKeyPath**: The path to the key of the HTTPS-certificate
* **CertificatePath**: The path to the HTTPS-certificate

Start up the master-gateway by calling

    ./Holmes-Gateway --master --config config-master.json


### Starting Gateway
Make sure, rabbitmq is running. If it isn't configured to automatically start, start it byexecuting as root:

    rabbitmq-server

Copy the file config.json.example to config.json and edit it to suit your needs.
The following configuration options are available:
* **HTTP**: The binding for the http-listener
* **SourcesKeysPath**: The path to where the public keys of the sources are found. The keys must be in PEM-format and must have the file-extension \*.pub
* **TicketKeysPath**: The public keys for tickets that should be acceptable
* **SampleStorageURI**: The URI where the samples reside. This URI is prepended to the PrimaryURI- and SecondaryURI-fields for incoming tasks
* **RabbitURI**: The URI to rabbt
* **RabbitUser**: The rabbit username
* **RabbitPassword**: The rabbit password
* **RabbitQueue**: The rabbit queue that is used for tasks
* **RoutingKey**: The rabbit routing key that is used for tasks
* **Exchange**: The rabbit exchange that is used for tasks

Start up the gateway by calling

    ./Holmes-Gateway --config config.json

## Uploading Samples:
In order to upload samples to storage, the user sends an https-encrypted request
to "/samples/" of the master-gateway. The master-gateway will forward every request
for this URI directly to storage.
If storage signals a success, master-gateway will immediately issue a tasking-request
for the new samples, if the configuration-option "AutoTasks" is not empty.

You can use [Holmes-Toolbox](https://github.com/HolmesProcessing/Holmes-Toolbox)
for this purpose. Just replace the storage-URI with the URI of master-gateway and
make sure, your SSL-Certificate is accepted.

## Requesting a Task:
In order to request a task, a user sends an https-request to the master-gateway
containing the following form-fields:
* **username**: The user's login-name
* **password**: The user's password
* **task**: The task which should be executed in json-form, as described below.

A task consists of the following attributes:
* **primaryURI**: The user enters only the sha256-sum here, as the Gateway will
prepend this with the URI to its version of Holmes-Storage
* **secondaryURI** (optional): A secondary URI to the sample, if the primaryURI isn't found
* **filename**: The name of the sample
* **tasks**: All the tasks that should be executed, as a dict
* **tags**: A list of tags associated with this task
* **attempts**: The number of attempts. Should be zero
* **source**: The source this sample belongs to. The executing organization is chosen mainly based on this value
