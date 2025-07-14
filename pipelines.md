## 1. Syslog to Sentinel pipeline

Go to the `Microsoft Sentinel Syslog` pack and copy the `sentinel_syslog` pipeline

![image](https://github.com/user-attachments/assets/aacd5bc8-89e4-4514-b8e5-8ab4bbca5f7e)

Paste the pipeline

![image](https://github.com/user-attachments/assets/9b66fd2f-55bb-4b47-beef-62416c2d2c8c)

![image](https://github.com/user-attachments/assets/e10cfdc6-6511-43c2-8177-7ed8b3d5ded0)

Edit the `Eval` step of the pipeline:
- Change `String(facility) || facilityName` to `facilityName` for the `Facility` field
  - Sentinel accepts `facilityName` (name) but not `facility` (number) for the `Facility` column
- Add field for `SourceSystem`: `'Cribl'`
- Add `SourceSystem` under `Keep fields`

![image](https://github.com/user-attachments/assets/76323605-88e5-43c8-aa07-a0d4b9a79327)

## 2. WEF to Sentinel pipeline

The `wef_security_events` pipeline from the `Microsoft Sentinel` pack would suffice for most of the mapping, but there are some columns that can be further improved

The adapted pipeline below tries to match the ingestion behaviour of security events ingested via AMA (Azure Monitor Agent)

### 2.0. Prepare lookup tables

A Windows security event ingested directly by AMA is enriched with information such as logon type name, event level name and activity.

This can be done in Cribl via the [Lookup](https://docs.cribl.io/stream/lookup-function/) function

Upload the csv to Knowledge → Lookups:
- [windows_logon_type.csv](/windows_logon_type.csv)
- [windows_event_level.csv](/windows_event_level.csv)
- [windows_event_id.csv](/windows_event_id.csv)

![image](https://github.com/user-attachments/assets/39af7a6f-8b4c-424f-aca9-50a86e121aa8)

### 2.1. Keep EventData in EventData field, parse Windows Event XML, drop input fields.

Function: [Eval](https://docs.cribl.io/stream/eval-function/)

Evaluate fields:

#### 2.1.1. EventData

```js
_raw.indexOf("<UserData>") > -1 ? _raw.substring(_raw.indexOf("<UserData>"),_raw.indexOf("</UserData>") + "</UserData>".length).replace(/Data>/g,"Data>\n") : _raw.substring(_raw.indexOf("<EventData>"),_raw.indexOf("</EventData>") + "</EventData>".length).replace(/Data>/g,"Data>\n")
```

#### 2.1.2. _raw

```js
C.Text.parseWinEvent(_raw,['0x0','-'])
```

Remove fields: `sourcetype` `source host` `sourceMachineID` `_time`

![image](https://github.com/user-attachments/assets/8f513290-6022-4a8e-8c22-d1584de8443a)

### 2.2. Flatten the fields under _raw to top level fields.

Function: [Flatten](https://docs.cribl.io/stream/flatten-function/)

![image](https://github.com/user-attachments/assets/57255e10-fac0-4590-b0ea-1a8c00f73282)

### 2.3. Rename to capture EventID field, remove prefixes and capture other required fields.

Function: [Rename](https://docs.cribl.io/stream/rename-function/)

#### 2.3.1. Rename expression (capture EventID field)

```js
name.replace(/^_raw_Event_System_EventID.*/,"EventID")
```

#### 2.3.2. Rename expression (remove prefixes)

```js
name.replace(/^_raw_Event.*_/,"")
```

#### 2.3.3. Rename fields (capture other required fields)

|Current Name|New Name|
|---|---|
|Name|EventSourceName|
|SystemTime| TimeGenerated|
|EventRecordID|EventRecordId|
|UserID|SystemUserId|
|ThreadID|SystemThreadId|
|ProcessID|SystemProcessId|

![image](https://github.com/user-attachments/assets/c338e23b-0d5b-4f3e-a768-015ab0870350)

### 2.4. Lookup to get LogonTypeName from LogonType and EventLevelName from Level.

#### 2.4.1. LogonTypeName

Lookup file path: `windows_logon_type.csv`

Lookup fields:

|Lookup Field Name in Event|Corresponding Field Name in Lookup|
|---|---|
|`LogonType`|`LogonType`|

|Output Field Name from Lookup|Lookup Field Name in Event|
|---|---|
|`LogonTypeName`|`LogonTypeName`|

#### 2.4.2. EventLevelName

Lookup file path: `windows_event_level.csv`

Lookup fields:

|Lookup Field Name in Event|Corresponding Field Name in Lookup|
|---|---|
|`Level`|`Level`|

|Output Field Name from Lookup|Lookup Field Name in Event|
|---|---|
|`EventLevelName`|`EventLevelName`|

![image](https://github.com/user-attachments/assets/ea6351b2-3e28-49d5-bc21-95b715f0d9e0)

### 2.5. Get message template from event ID and provider name.

The activity column is enriched in 2 steps:
1. [Lookup](https://docs.cribl.io/stream/lookup-function/) to [windows_event_id.csv](/windows_event_id.csv) to using event ID and provider name to get the message template and fields information, and place in `__message` and `__fields` fields
2. The next step uses the [Code](https://docs.cribl.io/stream/code-function/) function to fill in the fields into to the message template

Lookup file path: `windows_event_id.csv`

Lookup fields:

|Lookup Field Name in Event|Corresponding Field Name in Lookup|
|---|---|
|`EventID`|`event_code`|
|`EventSourceName`|`provider`|

|Output Field Name from Lookup|Lookup Field Name in Event|
|---|---|
|`template`|`__message`|
|`fields`|`__fields`|

This lookup function:
- selects the row with the event ID and provider combination (because different providers can happen to use the same event ID)
- returns the template and fields column
  - template: the message template, may contain `%1`, `%2`, etc placeholders for the specified fields depending on the event
  - fields: the fields to reference for each `%1`, `%2`, etc placeholders

![image](https://github.com/user-attachments/assets/2efdfffc-8b2d-4992-b0ac-374d8228726c)

### 2.6. Fill in field values to the message template.

A message template can contain 0 to N placeholders, this would need to have a loop or loopback function to map the fields to placeholders

The code function is required to perform this:
1. `__e.__fields.split(',')` converts the field names into an array
2. `.reduce((msg, field, index) => ...)` iterates through the array, applying transformations to `__e.__message`
3. `msg.replace(`%${index + 1}`, __e[field])` peplaces placeholders (`%1`, `%2`, etc.) in the message with corresponding values from `__e`

```js
__e.__message = __e.__fields.split(',').reduce((msg, field, index) => msg.replace(`%${index + 1}`, __e[field]), __e.__message)
```

> [!Tip]
>
> The special variable `__e` represents the `(context)` event inside a JavaScript expression.
> - Using `__e` with _square bracket notation_, can access any field within the event object (e.g. `__e['hostname']`)
> - In most cases, using `__e['field']` and `__e.field` are the same, but this notation **must be used** for fields that contain a special (non-alphanumeric) character like `user-agent`, `kubernetes.namespace_name`, or `@timestamp`
> 
> The special variable `__e` is useful in this case , consider below example event:
> 
> ```json
> {
>   "EventID": 145,
>   "Channel": "Microsoft-Windows-WinRM/Operational",
>   "Computer": "DC.lab.vx",
>   "Security_UserID": "S-1-5-20",
>   "__message": "WSMan operation %1 started with resourceUri %2",
>   "__fields": "operationName,resourceUri",
>   "operationName": "Enumeration",
>   "resourceUri": "http://schemas.microsoft.com/wbem/wsman/1/SubscriptionManager/Subscription",
>   "EventSourceName": "Microsoft-Windows-WinRM",
>   "Type": "SecurityEvent"
> }
> ```
>
> This JS produces `WSMan operation operationName started with resourceUri resourceUri`
> 
> ```js
>__message.replace('%1',__fields.split(',')[0]).replace('%2',__fields.split(',')[1])
> ```
>
> While this JS using `__e` produces `WSMan operation Enumeration started with resourceUri http://schemas.microsoft.com/wbem/wsman/1/SubscriptionManager/Subscription`
> 
> ```js
> __message.replace('%1',__e[__fields.split(',')[0]]).replace('%2',__e[__fields.split(',')[1]])
> ```

![image](https://github.com/user-attachments/assets/a6ef963b-e916-475e-abdd-9669999a8294)

### 2.7. Add some fields and drop unused ActivityID and Provider Guid fields.

#### 2.7.1. Trim message and concatenate to event ID

Several of the message templates are multi-line, the first line would be sufficient to enrich the event with activity information

[Eval](https://docs.cribl.io/stream/eval-function/) can be used to:
- Keep only the first line by checking for `\r\r\n` and then using `substring()` to trim `__message`
- Appending `EventID` with `__message` can be done via template literal or string concatenation

Template literal:

```js
`${EventID} - ${__message.indexOf('\\r\\r\\n') > -1 ? __message.substring(0,__message.indexOf('\\r\\r\\n')) : __message.substring(0,__message.length)}`
```

String concatenation:

```js
EventID + ' - ' + (__message.indexOf('\\r\\r\\n') > -1 ? __message.substring(0,__message.indexOf('\\r\\r\\n')) : __message.substring(0,__message.length))
```

#### 2.7.2. Enrich event with more fields

Other than the activity field above, [Eval](https://docs.cribl.io/stream/eval-function/) is also used to add accounts-related and other information to the event

Evaluate fields:

|Name|Value Expression|
|---|---|
|SubjectAccount|`SubjectDomainName && SubjectUserName ? SubjectDomainName + '\\' + SubjectUserName : null`|
|TargetAccount|`TargetDomainName && TargetUserName ? TargetDomainName + '\\' + TargetUserName : null`|
|Account|`TargetAccount \|\| SubjectAccount ? (TargetAccount ? TargetAccount : SubjectAccount) : null`|
|AccountType|`Account ? (/NT Service\|NT AUTHORITY\|\$/.test(Account) ? 'Machine' : 'User') : null`|
|Process|`ProcessName \|\| NewProcessName ? (ProcessName ? ProcessName.substring(ProcessName.lastIndexOf('\\')+1) : NewProcessName.substring(NewProcessName.lastIndexOf('\\')+1)) : null`|
|LogonGuid|`LogonGuid.replaceAll("{","").replaceAll("}","")`|
|SourceSystem|`'Cribl'`|
|Type|`'SecurityEvent'`|

Remove fields: `ActivityID` `Guid`

#### 2.7.3. Numerify all number values

Numerify all number values except `Level`; for some reason, the `Level` column of `SecurityEvent` in Sentinel is of `string` type

![image](https://github.com/user-attachments/assets/078a3034-b99f-4b12-bf38-d5e5581ebaa8)
