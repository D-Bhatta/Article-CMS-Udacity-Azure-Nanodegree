# Write-up Template

## Analyze, choose, and justify the appropriate resource option for deploying the app

*For **both** a VM or App Service solution for the CMS app:*

- *Analyze costs, scalability, availability, and workflow*
- *Choose the appropriate solution (VM or App Service) for deploying the app*
- *Justify your choice*

## Analysis of VM

- A VM such as D2 v3 with 2 vCPUs, 8 GB RAM, 50 GB Temporary storage,  at $0.117/hour will cost around $85 per month.
- A VM can be scaled up easily, both veritcally by moving to a higher tier of VM and horizontally by provisioning more servers.
- Costs are constant, and increase linearly with the number of servers.
- A VM would need maintenance and availability depends on qualtiy of managed service.
- Code can be deployed via a github action that SSH into the server and updates the local repo and restarts the process.

## Analysis of App Service

- An app service at B3 tier with  4 Cores(s), 7 GB RAM, 10 GB Storage,  at $0.071/hour will cost around $65 per month.
- It can be easily scaled up vertically by moving to a premium tier.
- Costs are constant per hour of use.
- App services will not need maintenance, since those are provided by Azure.
- Code can be deployed from a github action, and the app service restarted.

## Why I chose an App Service

- App is currently small, and performance requirements are low.
- App service can easily fulfill all performance requirements in terms of infrastructure as the app scales.
- Auto scaling can be enabled.
- App service will cost less for each hour.
- Thus, it would be more economically efficient to use an app service for deployment instead of a VM.

## Assess app changes that would change your decision

*Detail how the app and any other needs would have to change for you to change your decision in the last section.*

I would choose a VM based solution over an App Service if any of the following conditions are satisfied:

- The performance requirements for the app exceed the highest tier offered by App Service SKU.
- The cost of using the App Service SKU exceeds the cost of deploying to a VM.
- The complexity of the app grows and demands use of a more flexible environment, which a VM can offer.
