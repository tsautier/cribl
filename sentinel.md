Ref:
- https://docs.cribl.io/stream/usecase-azure-workspace/
- https://docs.cribl.io/stream/destinations-sentinel/

## 1. Setup Entra Identity for Cribl

### 1.1. Create app registration

> [!Note]
>
> Take note of the `Application (client) ID` and `Directory (tenant) ID`; these will be required later.

![image](https://github.com/user-attachments/assets/59e8dbc2-3d70-465e-abd3-b1b4e2b82a6e)

### 1.2. Create client secret

> [!Important]
>
> The client secret is displayed **only once**, copy and store it securely right after creation
>
> There is no way to retrieve the client secret if it's lost, it will need to be deleted and create a new one

![image](https://github.com/user-attachments/assets/460af096-e666-454f-b786-25dad9d0489c)

## 2. Setup data collection

### 2.1. Create DCE (Data Collection Endpoint)

![image](https://github.com/user-attachments/assets/7d4bf64a-c578-4e21-85e1-8ef69c530135)

### 2.2. Create DCR (Data Collection Rule) using [Cribl DCR template](https://docs.cribl.io/stream/usecase-webhook-azure-sentinel-dcr-template/)

#### 2.2.1. Required information for the DCR

DCR Resource ID:

![image](https://github.com/user-attachments/assets/cc6c6a0d-f36c-4fce-9ffa-dabfdc15dc7c)

Target LAW (Log Analytics Workspace) Resource ID:

![image](https://github.com/user-attachments/assets/5d23f14b-c070-429a-882c-1da525d70367)

#### 2.2.2. DCR template

Cribl uses the [logs ingestion API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview) to push events to Sentinel and provides a [DCR template](https://docs.cribl.io/stream/usecase-webhook-azure-sentinel-dcr-template/) to implement the DCR data flow

More details on [DCR data flow](https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/data-collection-rule-structure#overview-of-dcr-data-flow)

A DCR template with complete mapping of columns to Sentinel tables is availabled here: [dcr_template.json](https://github.com/joetanx/sentinel/blob/main/dcr_template.json)

#### 2.2.3. Deploy the DCR template

- Go to `Deploy a custom template`
- Select `Build your own template in the editor`
- Copy and paste the [dcr_template.json](https://github.com/joetanx/sentinel/blob/main/dcr_template.json)

![image](https://github.com/user-attachments/assets/447710cf-fe0a-4c83-84ac-f3489af66d8e)

Paste the DCE and LAW Resource IDs

![image](https://github.com/user-attachments/assets/c6e1a4b6-e82f-4a1e-8a37-49ea976caac4)

### 2.3. Add role assignment for Cribl to the DCR

> [!Note]
>
> In Entra, app registration contains information about the application, usually including URLs for SSO (Single Sign-On)
>
> An enterprise application is created automatically when an app is registered
>
> The enterprise application resource is the service prinicipal (i.e. service account or machine identity) of the application
>
> Permissions can be granted to the application by role assignment to the application resource

DCR → Access Control (IAM) → Add role assignment

Select `Monitoring Metrics Publisher` role:

![image](https://github.com/user-attachments/assets/39ccce1b-7e13-4dbc-b8e1-892d910d81a4)

Select the Cribl application:

> [!Tip]
>
> https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal#assign-a-role-to-the-application
>
> By default, Microsoft Entra applications aren't displayed in the available options. Search for the application by name to find it.

![image](https://github.com/user-attachments/assets/8082053c-80f6-4852-a02a-8670258713a5)

### 2.4. Retrieve the logs ingestion API URI

Ref: https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview#uri

The URI consists of:
- DCE
- Region
- DCR Immutable ID
- Stream Name
- API version

```pwsh
{Endpoint}.{Region}.ingest.monitor.azure.com//dataCollectionRules/{DCR Immutable ID}/streams/{Stream Name}?api-version=2023-01-01
```

|Field|Description|
|---|---|
|Data collection endpoint|Data collection endpoint (DCE) in the format `https://<endpoint-name>.<identifier>.<region>.ingest.monitor.azure.com`.<br>![image](https://github.com/user-attachments/assets/66bdcfde-8afe-4073-b288-753a37e276f0)|
|Data collection rule ID|DCR Immutable ID:<br>![image](https://github.com/user-attachments/assets/ca1ad029-3eaf-476a-b3db-f404c1381225)|
|Stream name|The `streamDeclarations` defined in the DCR:<<br>![image](https://github.com/user-attachments/assets/eec7c4a2-5d68-4924-9ea8-48e391bf3fc0)|

Cribl provides a Azure Resource Graph Explorer [query](https://docs.cribl.io/stream/usecase-azure-sentinel/#obtaining-url) to retrieve the required information

```kusto
Resources
| where type =~ 'microsoft.insights/datacollectionrules'
| mv-expand Streams= properties['dataFlows']
| project name, id, DCE = tostring(properties['dataCollectionEndpointId']), ImmutableId = properties['immutableId'], StreamName = Streams['streams'][0]
| join kind=leftouter (Resources
| where type =~ 'microsoft.insights/datacollectionendpoints'
| project name,  DCE = tostring(id), endpoint = properties['logsIngestion']['endpoint']) on DCE
| project name, StreamName, Endpoint = strcat(endpoint, '/dataCollectionRules/',ImmutableId,'/streams/',StreamName,'?api-version=2023-01-01')
```

![image](https://github.com/user-attachments/assets/74a62ad5-6624-48fc-916e-6db06bab8653)

## 3. Configure data destination to Sentinel in Cribl

![image](https://github.com/user-attachments/assets/d7809f46-bf50-4bd6-b8ea-fb21cf28a6a1)

### 3.1. General Settings

Configuration of Sentinel as data destination in Cribl can be done using `URL` or `ID`

![image](https://github.com/user-attachments/assets/9f73730b-913c-422d-a781-0ab2c63985c0)

![image](https://github.com/user-attachments/assets/d713c4e6-2d28-400b-a0cc-b9ef30d59352)

![image](https://github.com/user-attachments/assets/b8abdaa9-a0a1-4727-8625-1105250a655f)

![image](https://github.com/user-attachments/assets/caa38a91-ce86-446e-b114-a08dd28a6965)

### 3.2. Authentication

|Field|Description|
|---|---|
|Login URL|The token API endpoint for the Microsoft identity platform. Use the string: `https://login.microsoftonline.com/<tenant_id>/oauth2/v2.0/token`, substituting `<tenant_id>` with Entra ID tenant ID.<br>The Directory (tenant) ID listed on the app's Overview page.<br>![image](https://github.com/user-attachments/assets/ff222c63-9d14-4684-b89f-09b27b7841c2)|
|OAuth secret|The client secret generated in [1.2. Create client secret](#12-create-client-secret)|
|Client ID|The Application (client) ID listed on the app's Overview page.<br>![image](https://github.com/user-attachments/assets/2efa1a5e-237d-4e89-9ca8-443cc665c7ce)|

> [!Tip]
>
> The client ID is entered as a json constant (i.e. enclosing the value with backticks <code>`</code>)

![image](https://github.com/user-attachments/assets/f94accb8-1aa5-4d3c-9b47-dd4d2303a511)

### 3.3. Test the data destination

![image](https://github.com/user-attachments/assets/2f8c3e00-2b8a-495e-9e19-3b44413cf996)

![image](https://github.com/user-attachments/assets/f7378b65-6b64-4957-88c1-11dde58559d3)

## 4. Get Cribl packs for Sentinel

There are a couple of Sentinel packs in the Dispensary that works out of the box

Processing → Packs → Add Pack → Add from Dispensary

![image](https://github.com/user-attachments/assets/4962989e-2170-4c9a-b149-a27ef94d15db)

Search for `Sentinel`

![image](https://github.com/user-attachments/assets/0cd81a54-ebb1-4a80-8579-ac3d932fd6d9)

The `Microsoft Sentinel` pack by Christoph Dittmann (cdittmann@cribl.io) includes a wef pipeline to parse Windows events to columns in the SecurityEvent table

![image](https://github.com/user-attachments/assets/d9597558-7730-4f41-b975-2a637d05baab)

The `Microsoft Sentinel Syslog` pack by Dan Schmitz (dschmitz@cribl.io) includes a syslog pipeline to parse syslog events to columns in the Syslog table

![image](https://github.com/user-attachments/assets/7584645f-e036-4afb-8a1f-d19d2984a407)

### 4.1. Customize pipelines to transform events to Sentinel

While the packs work out of the box in sending events to Sentinel, some fine-tuning can be done to tweak such that the details sent by Cribl aligns with events sent via AMA.

The fine-tuning can be found here: https://github.com/joetanx/cribl/edit/main/pipelines.md

## 5. Configure routes

|Route|Source|Pipeline|Destination|
|---|---|---|---|
|route_wef_to_sentinel|`__inputId=='wef:in_wef'`|sentinel_wef_securityevent|sentinel:out_sentinel_securityevent|
|route_syslog_to_sentinel|`__inputId.startsWith('syslog:in_syslog:')`|sentinel_syslog|sentinel:out_sentinel_syslog|

![image](https://github.com/user-attachments/assets/a303b5fd-16ef-4a77-8a95-ab5fcb56f500)

## 6. Verify data flow in Cribl

Sources:

![image](https://github.com/user-attachments/assets/52c7c967-77ba-4311-a7f0-4801604fda8c)

Routes:

![image](https://github.com/user-attachments/assets/dca1d4ca-e959-47c6-8abd-44713e8b2325)

Pipelines:

![image](https://github.com/user-attachments/assets/a98e9caa-e4a6-48b7-8477-a6e76468d729)

Destinations:

![image](https://github.com/user-attachments/assets/e470a829-5a7e-410f-b95f-62503101a173)

## 7. Verify events ingested in Sentinel

SecurityEvent table:

![image](https://github.com/user-attachments/assets/96725170-00a4-45ae-839c-c07de3cad904)

Syslog table:

![image](https://github.com/user-attachments/assets/2bff8a08-5c80-4cc1-98ed-e1e52231d128)
