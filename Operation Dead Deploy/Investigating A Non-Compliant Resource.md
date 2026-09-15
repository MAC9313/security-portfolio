# Operation Dead Deploy | Governance forensics, deployment audit trail

## Scenario
A non-compliant resource group (rg) was created under the Mad Hat Labs subscription. The objective is to find out who is responsible for creation, what was deployed within the rg, when the rg was created, why and how the rg was allowed to be deployed in the first place.
## Environment
In a live multi-user Azure training tenant, maintaining reader access over the Mad Hat Subscription. RG's in the environment are created using "rg-\*" as a prefix, anything that does not utilize this naming convention is a finding and should be investigated further.  

## Investigation
1. Navigated to Resource Groups in the Azure portal to gain an inventory of the rgs in the environment. It is immediately apparent that there is an anomaly in the list that doesn't follow the organizations required naming convention. 

<br>

![](attachments/Pasted%20image%2020260913213551.png)


<br>

Azure Powershell:

```Powershell
Get-AzResourceGroup | Select-Object ResourceGroupName, Location
```

---
 
 2. Proceeded to look into the RG using the incorrect naming convention, there is one resource created that provides the answer as to who was responsible for its inception. Through the tags, it can be seen that the storage account was created by an intern at 05/04/2026 at 02:42:25 PM. 
 
<br>

![](attachments/Pasted%20image%2020260913214614.png)

<br>


Azure Powershell:

```Powershell
Get-AzResource -ResourceGroupName <rg_name> | Select-Object ResourceName, Kind, Location, TagsTable | Format-List
```

---

3. Following the finding of a storage account, the next step is identifying the audit trail of the resource through the Deployments section that can be located on the rg's overview page.
<br>

![](attachments/Pasted%20image%2020260913215911.png)

<br>


Azure Powershell:

```Powershell
Get-AzResourceGroupDeployment -ResourceGroupName <rg_name> | Select-Object DeploymentName, Timestamp, ProvisioningState, Mode, CorrelationId
```

---


4. Finally, it is necessary to know why this rg was able to be created in the first place with the incorrect naming convention. By navigating to the Policy blade on the rg, there is a Naming Convention policy in effect that requires all rgs to use the naming convention "rg-\*" . When observing the policy, it can be seen that the effect type is on Audit and not Enforced, therefore the out of compliance rg was allowed to be created.       

<br>

![](attachments/Pasted%20image%2020260913221457.png)


<br>
Azure Powershell (Validated AI Command Flow):
	

```Powershell
$rg = <resource_group>

# ARM identifies scope through a resource ID string
$scope = (Get-AzResourceGroup -Name $rg).ResourceId

# List policy assignments affecting this scope, including inherited management and subscription group assignments
Get-AzPolicyAssignment -Scope $scope | Select Name, DisplayName, EnforcementMode, Scope

# Use the DisplayName value for the Naming Convention Policy
$a = Get-AzPolicyAssignment -Scope $scope | Where DisplayName -eq "Naming Convention"

# Checking if the assignment overwrote the effect. If returns {}, then move to the next command.
$a.Parameter | ConvertToJson -Depth 5

# Retreive the policy definition that the Naming assignment points to
$d = Get-AzPolicyDefinition -Id $a.PolicyDefinitionId

# The definition of the policies default effect and what values are available
$d.Parameter | ConvertTo-JSON -Depth 5

# The rule that is applied to the Naming Convention policy
$d.PolicyRule | ConvertTo-Json -Depth 10

# Policy engines evaluation record confirmation check
Get-AzPolicyState -ResourceGroupName $rg | Where PolicyAssignmentName -eq $a.Name | Select PolicyAssignmentName, PolicyDefinitionAction, ComplianceState, ResourceId
```

<br>

![](attachments/Pasted%20image%2020260914204621.png)

<br>

## What broke / what surprised me
This wasn't a sophisticated adversary that spun up a new rg and deployed a storage account for data exfiltration. This was an intern given excessive permissions with no oversight, whom created a non-compliant object. Additionally, this was able to happen through a misconfiguration in policy that allowed the improperly named rg to be created. 

## Findings and recommendations
It was determined that an intern was given excessive permissions and created a non-compliant rg due to a policy being set to audit instead of enforced. In the future, it is recommended that if an intern is given permissions to create resources in the environment that this is done under a specified time window and under guided supervision from an intermediate or senior operative. This would ensure that a test environment wouldn't be left sitting over the weekend, incurring unnecessary costs to the organization. Additionally and most importantly, proper validation of policy enforcement is necessary as a policy that should be enforced, but is left on audit could allow an adversary to find a weakness or vulnerability that allows for initial access and/or increase the blast radius of an attack. For example, if MFA was set on audit, then all the adversary would need was the users password to gain entry into Azure environment.

## What I learned
- The principle of least privilege is not a recommendation, it is necessary to prevent junior operatives from creating non-compliant resources. In this scenario, it was a simple naming enforcement that failed. In the next incident, maybe a resource is assigned a public IP address that gives an adversary their initial foothold in the network. 
- Just in time permissions could've prevented this unauthorized behavior. The junior was given permissions to create a test rg, but they should not have been able to create one on a Friday at 02:42 PM. Depending on the resource, there could be a significant charge incurred over the weekend. 
- Policy enforcement needs to be consistently validated to ensure that the environment is not just portraying the illusion of security, but is actually preventing the behavior and actions that the Security team is expecting it to. Adversaries, especially sophisticated ones act quickly when they gain initial access into an environment. Reading the audit log and finding out that there was a breach that led to data exfiltration or ransomware that was caused by policy oversight would be a hard pill to swallow.
- Something as simple as a deviation from a naming convention can be the anomaly needed to jumpstart an investigation. After spotting the rg with the incorrect name, it was able to be determined who created the rg, and what time that the resource was created. This would be beneficial in correlating events in a SIEM for the specific account in question to look into what took place before and after deployment.
