export type Tone = "neutral" | "healthy" | "warning" | "critical" | "info";

export interface NavigationItem {
  id: string;
  label: string;
  route: string;
  icon: string;
  pageId: string;
  keywords: string[];
}

export interface NavigationGroup {
  id: string;
  label: string;
  items: NavigationItem[];
}

export interface ColumnDefinition {
  key: string;
  label: string;
  format?: "text" | "status" | "bytes" | "number" | "date" | "duration" | "hostname";
  width?: string;
}

export interface FieldDefinition {
  key: string;
  label: string;
  type: "text" | "email" | "password" | "number" | "boolean" | "select" | "textarea" | "hostname" | "cidr" | "cron";
  required?: boolean;
  options?: Array<{ label: string; value: string }>;
  helper?: string;
  defaultValue?: unknown;
}

export interface ActionDefinition {
  id: string;
  label: string;
  operation: string;
  tone?: Tone;
  mutating: boolean;
  assurance?: "password" | "mfa" | "phishing_resistant";
  fields?: FieldDefinition[];
  confirmation?: string;
  resourceTypes?: string[];
}

export interface PageDefinition {
  id: string;
  title: string;
  description: string;
  resourceKind: string;
  listOperation: string;
  detailOperation?: string;
  createAction?: ActionDefinition;
  rowActions?: ActionDefinition[];
  globalActions?: ActionDefinition[];
  columns: ColumnDefinition[];
  emptyTitle: string;
  emptyBody: string;
}

const lifecycleActions = (prefix: string): ActionDefinition[] => [
  { id: "suspend", label: "Suspend", operation: `${prefix}.suspend`, mutating: true, tone: "warning", confirmation: "New application traffic and scheduled work will stop. Stored data remains intact." },
  { id: "resume", label: "Resume", operation: `${prefix}.resume`, mutating: true, tone: "healthy" },
  { id: "delete", label: "Delete", operation: `${prefix}.delete`, mutating: true, tone: "critical", assurance: "mfa", confirmation: "The resource will be quarantined first, then purged after the configured retention window." }
];

export const pages: Record<string, PageDefinition> = {
  dashboard: {
    id: "dashboard", title: "Operational overview", description: "Live node health, workload pressure, risk, and unfinished operations.", resourceKind: "dashboard",
    listOperation: "dashboard.summary", columns: [], emptyTitle: "No node data yet", emptyBody: "The local node is still publishing its first health projection."
  },
  sites: {
    id: "sites", title: "Sites", description: "Web applications, domain bindings, PHP runtimes, limits, and lifecycle.", resourceKind: "hosting.site", listOperation: "hosting.site.list", detailOperation: "hosting.site.get",
    createAction: { id: "create", label: "Create site", operation: "hosting.site.create", mutating: true, fields: [
      { key: "primary_hostname", label: "Primary hostname", type: "hostname", required: true },
      { key: "project_id", label: "Project", type: "text", required: true },
      { key: "php_profile", label: "PHP runtime", type: "select", required: true, options: [{label:"PHP 8.4",value:"php84"},{label:"PHP 8.3",value:"php83"},{label:"PHP 8.2",value:"php82"}] }
    ] },
    columns: [{key:"primary_hostname",label:"Site",format:"hostname"},{key:"lifecycle",label:"State",format:"status"},{key:"php_profile",label:"Runtime"},{key:"disk_usage",label:"Disk",format:"bytes"},{key:"bandwidth",label:"Transfer",format:"bytes"},{key:"updated_at",label:"Updated",format:"date"}],
    rowActions: [{id:"preview",label:"Preview",operation:"hosting.site.preview.issue",mutating:true,tone:"info"},{id:"clone",label:"Clone",operation:"hosting.site.clone",mutating:true},...lifecycleActions("hosting.site")], emptyTitle:"No sites",emptyBody:"Create the first isolated site on this node."
  },
  domains: {
    id:"domains",title:"Domains & routes",description:"Primary domains, aliases, redirects, child applications, access policies, and previews.",resourceKind:"hosting.binding",listOperation:"hosting.binding.list",
    createAction:{id:"attach",label:"Attach domain",operation:"hosting.binding.create",mutating:true,fields:[{key:"site_id",label:"Site",type:"text",required:true},{key:"hostname",label:"Hostname",type:"hostname",required:true},{key:"relationship",label:"Relationship",type:"select",required:true,options:[{label:"Alias",value:"alias"},{label:"Child application",value:"child"},{label:"Redirect",value:"redirect"}]}]},
    columns:[{key:"hostname",label:"Hostname",format:"hostname"},{key:"relationship",label:"Type"},{key:"site",label:"Site"},{key:"tls",label:"TLS",format:"status"},{key:"routing",label:"Routing",format:"status"},{key:"updated_at",label:"Updated",format:"date"}],
    rowActions:[{id:"tls",label:"Issue TLS",operation:"certificate.site.issue",mutating:true},{id:"password",label:"Access policy",operation:"hosting.binding.access_policy",mutating:true},{id:"delete",label:"Detach",operation:"hosting.binding.delete",mutating:true,tone:"critical",confirmation:"Traffic for this hostname will stop after the guarded engine activation."}],emptyTitle:"No additional domains",emptyBody:"Aliases, redirects, and child applications appear here."
  },
  wordpress: {
    id:"wordpress",title:"Applications",description:"Certified WordPress, Joomla, PrestaShop, Mautic, and Magento installs with signed releases, health, updates, recovery, and security.",resourceKind:"apps.instance",listOperation:"apps.instance.list",
    createAction:{id:"install",label:"Install app",operation:"apps.instance.install",mutating:true,assurance:"mfa",fields:[{key:"site_id",label:"Site",type:"text",required:true},{key:"application",label:"Application",type:"select",required:true,defaultValue:"wordpress",options:[{label:"WordPress",value:"wordpress"},{label:"Joomla",value:"joomla"},{label:"PrestaShop",value:"prestashop"},{label:"Mautic",value:"mautic"},{label:"Magento Open Source",value:"magento"}]},{key:"version",label:"Certified version",type:"text",required:true,helper:"The matching signed recipe is selected from the node's pinned catalog."},{key:"administrator_username",label:"Administrator username",type:"text",required:true},{key:"administrator_email",label:"Administrator email",type:"text",required:true},{key:"administrator_display_name",label:"Administrator display name",type:"text",required:true},{key:"administrator_password",label:"Administrator password",type:"password",required:true,helper:"Used once during bootstrap, stored only in the protected secret broker, then revoked."},{key:"locale",label:"Locale",type:"text",required:true,defaultValue:"en_US"},{key:"timezone",label:"Timezone",type:"text",required:true,defaultValue:"UTC"},{key:"title",label:"Site title",type:"text"}]},
    columns:[{key:"hostname",label:"Application"},{key:"type",label:"Type"},{key:"version",label:"Version"},{key:"health",label:"Health",format:"status"},{key:"updates",label:"Updates",format:"number"},{key:"last_backup",label:"Last recovery point",format:"date"}],
    rowActions:[{id:"login",label:"Secure login",operation:"apps.wordpress.autologin.issue",mutating:true,tone:"info",resourceTypes:["wordpress"]},{id:"update",label:"Update",operation:"apps.instance.update",mutating:true,fields:[{key:"version",label:"Certified target version",type:"text",required:true,helper:"The matching signed recipe is selected from the node's pinned catalog."}]},{id:"cache",label:"Purge cache",operation:"apps.wordpress.cache.purge",mutating:true,resourceTypes:["wordpress"],fields:[{key:"scope",label:"Purge scope",type:"select",required:true,defaultValue:"all",options:[{label:"Everything",value:"all"},{label:"Paths",value:"path"},{label:"Cache tags",value:"tag"}]},{key:"values",label:"Paths or tags",type:"textarea",helper:"Enter one value per line. Leave empty when purging everything."}]},{id:"scan",label:"Scan",operation:"apps.scan.start",mutating:true,fields:[{key:"mode",label:"Scan depth",type:"select",required:true,defaultValue:"quick",options:[{label:"Quick",value:"quick"},{label:"Full",value:"full"},{label:"Integrity comparison",value:"integrity_comparison"}]}]},{id:"remove",label:"Remove",operation:"apps.instance.remove",mutating:true,tone:"critical",assurance:"mfa",confirmation:"A verified recovery point is created before the application files and managed database are purged."}],emptyTitle:"No managed applications",emptyBody:"Install a certified application on an existing site."
  },
  databases: {
    id:"databases",title:"Databases",description:"MariaDB databases, principals, exact grants, network access, tuning, and console sessions.",resourceKind:"database.database",listOperation:"database.database.list",
    createAction:{id:"create",label:"Create database",operation:"database.database.create",mutating:true,fields:[{key:"site_id",label:"Site",type:"text",required:true},{key:"name",label:"Database name",type:"text",required:true},{key:"charset",label:"Character set",type:"select",required:true,options:[{label:"utf8mb4",value:"utf8mb4"},{label:"utf8",value:"utf8"}]}]},
    columns:[{key:"name",label:"Database"},{key:"site",label:"Site"},{key:"instance",label:"Instance"},{key:"size",label:"Size",format:"bytes"},{key:"principals",label:"Principals",format:"number"},{key:"status",label:"Status",format:"status"}],
    rowActions:[{id:"browse",label:"Open console",operation:"database.console.issue",mutating:true,tone:"info"},{id:"principal",label:"Add principal",operation:"database.principal.create",mutating:true},{id:"remote",label:"Network access",operation:"database.network.configure",mutating:true,assurance:"mfa"},{id:"delete",label:"Delete",operation:"database.database.delete",mutating:true,tone:"critical",assurance:"mfa"}],emptyTitle:"No databases",emptyBody:"Create a database with an isolated principal and exact grant set."
  },
  files: {
    id:"files",title:"Files & deployments",description:"Site-root file operations, uploads, archives, trash, Git deployments, and staging sync.",resourceKind:"access.file",listOperation:"access.files.list",
    createAction:{id:"upload",label:"Upload",operation:"access.upload.begin",mutating:true,fields:[{key:"site_id",label:"Site",type:"text",required:true},{key:"destination",label:"Destination",type:"text",required:true}]},
    columns:[{key:"name",label:"Name"},{key:"type",label:"Type"},{key:"size",label:"Size",format:"bytes"},{key:"mode",label:"Mode"},{key:"modified_at",label:"Modified",format:"date"}],
    rowActions:[{id:"edit",label:"Edit",operation:"access.file.write",mutating:true},{id:"download",label:"Download",operation:"access.download.issue",mutating:true},{id:"archive",label:"Archive",operation:"access.archive.create",mutating:true},{id:"trash",label:"Move to trash",operation:"access.file.trash",mutating:true,tone:"warning"}],emptyTitle:"Select a site",emptyBody:"Choose a site root to browse files without exposing host paths."
  },
  access: {
    id:"access",title:"FTP, SSH & terminal",description:"FTPS accounts, SSH/SFTP keys, access grants, active sessions, and tenant terminals.",resourceKind:"access.credential",listOperation:"access.credential.list",
    createAction:{id:"create",label:"Add access",operation:"access.credential.create",mutating:true,fields:[{key:"site_id",label:"Site",type:"text",required:true},{key:"kind",label:"Access kind",type:"select",required:true,options:[{label:"SFTP / SSH key",value:"ssh_key"},{label:"FTPS account",value:"ftps"},{label:"Terminal grant",value:"terminal"}]},{key:"label",label:"Label",type:"text",required:true}]},
    columns:[{key:"label",label:"Credential"},{key:"kind",label:"Type"},{key:"site",label:"Site"},{key:"last_used_at",label:"Last used",format:"date"},{key:"expires_at",label:"Expires",format:"date"},{key:"state",label:"State",format:"status"}],
    rowActions:[{id:"rotate",label:"Rotate",operation:"access.credential.rotate",mutating:true},{id:"session",label:"Open terminal",operation:"access.terminal.issue",mutating:true,tone:"info",assurance:"mfa"},{id:"revoke",label:"Revoke",operation:"access.credential.revoke",mutating:true,tone:"critical"}],emptyTitle:"No access credentials",emptyBody:"Issue a scoped credential or one-time terminal grant."
  },
  backups: {
    id:"backups",title:"Backup & recovery",description:"Policies, repositories, verified recovery points, retention, restores, and transfers.",resourceKind:"backup.policy",listOperation:"backup.policy.list",
    createAction:{id:"create",label:"Create policy",operation:"backup.policy.create",mutating:true,fields:[{key:"scope",label:"Site or tenant",type:"text",required:true},{key:"schedule",label:"Schedule",type:"cron",required:true},{key:"repository_id",label:"Repository",type:"text",required:true},{key:"retention",label:"Retention policy",type:"text",required:true}]},
    columns:[{key:"name",label:"Policy"},{key:"scope",label:"Scope"},{key:"repository",label:"Repository"},{key:"last_run",label:"Last run",format:"date"},{key:"last_result",label:"Result",format:"status"},{key:"next_run",label:"Next run",format:"date"}],
    rowActions:[{id:"run",label:"Run now",operation:"backup.run.start",mutating:true,tone:"info"},{id:"points",label:"Recovery points",operation:"backup.recovery_point.list",mutating:false},{id:"restore",label:"Plan restore",operation:"backup.restore.plan",mutating:true,assurance:"mfa"},{id:"delete",label:"Delete policy",operation:"backup.policy.delete",mutating:true,tone:"critical"}],emptyTitle:"No backup policies",emptyBody:"Create a policy with a verified destination and explicit retention."
  },
  dns: {
    id:"dns",title:"DNS",description:"PowerDNS zones, records, primary/secondary transfers, provider sync, and DNSSEC.",resourceKind:"dns.zone",listOperation:"dns.zone.list",
    createAction:{id:"create",label:"Create zone",operation:"dns.zone.create",mutating:true,fields:[{key:"name",label:"Zone name",type:"hostname",required:true},{key:"mode",label:"Mode",type:"select",required:true,options:[{label:"Native",value:"native"},{label:"Primary",value:"primary"},{label:"Secondary",value:"secondary"}]}]},
    columns:[{key:"name",label:"Zone",format:"hostname"},{key:"mode",label:"Mode"},{key:"records",label:"Records",format:"number"},{key:"serial",label:"Serial",format:"number"},{key:"dnssec",label:"DNSSEC",format:"status"},{key:"health",label:"Health",format:"status"}],
    rowActions:[{id:"records",label:"Records",operation:"dns.recordset.list",mutating:false},{id:"import",label:"Import",operation:"dns.zone.import",mutating:true},{id:"dnssec",label:"DNSSEC",operation:"dns.dnssec.configure",mutating:true,assurance:"mfa"},{id:"delete",label:"Delete",operation:"dns.zone.delete",mutating:true,tone:"critical"}],emptyTitle:"No DNS zones",emptyBody:"Create a local authoritative zone or bind an external provider."
  },
  certificates: {
    id:"certificates",title:"Certificates",description:"ACME accounts, orders, challenges, immutable generations, deployment, and renewal.",resourceKind:"certificate.certificate",listOperation:"certificate.list",
    createAction:{id:"issue",label:"Issue certificate",operation:"certificate.issue",mutating:true,fields:[{key:"consumer",label:"Site, panel, or mail consumer",type:"text",required:true},{key:"names",label:"DNS names",type:"textarea",required:true},{key:"challenge",label:"Challenge",type:"select",required:true,options:[{label:"HTTP-01",value:"http-01"},{label:"DNS-01",value:"dns-01"}]}]},
    columns:[{key:"names",label:"Names"},{key:"issuer",label:"Issuer"},{key:"consumer",label:"Consumer"},{key:"not_after",label:"Expires",format:"date"},{key:"renewal",label:"Renewal",format:"status"},{key:"generation",label:"Generation",format:"number"}],
    rowActions:[{id:"renew",label:"Renew",operation:"certificate.renew",mutating:true},{id:"deploy",label:"Deploy",operation:"certificate.deploy",mutating:true},{id:"revoke",label:"Revoke",operation:"certificate.revoke",mutating:true,tone:"critical",assurance:"mfa"}],emptyTitle:"No managed certificates",emptyBody:"Issue a certificate for a site, mail service, or panel hostname."
  },
  mail: {
    id:"mail",title:"Mail",description:"Domains, mailboxes, aliases, limits, DKIM, relay, queue, logs, and diagnostics.",resourceKind:"mail.domain",listOperation:"mail.domain.list",
    createAction:{id:"domain",label:"Add mail domain",operation:"mail.domain.create",mutating:true,fields:[{key:"domain",label:"Domain",type:"hostname",required:true},{key:"site_id",label:"Owning site",type:"text",required:true},{key:"dns_automation",label:"Configure DNS records",type:"boolean",defaultValue:true}]},
    columns:[{key:"domain",label:"Domain",format:"hostname"},{key:"mailboxes",label:"Mailboxes",format:"number"},{key:"quota_used",label:"Usage",format:"bytes"},{key:"dkim",label:"DKIM",format:"status"},{key:"delivery",label:"Delivery",format:"status"},{key:"health",label:"Health",format:"status"}],
    rowActions:[{id:"mailbox",label:"Add mailbox",operation:"mail.mailbox.create",mutating:true},{id:"aliases",label:"Aliases & routing",operation:"mail.route.list",mutating:false},{id:"diagnose",label:"Diagnose",operation:"mail.diagnostic.run",mutating:true},{id:"delete",label:"Delete",operation:"mail.domain.delete",mutating:true,tone:"critical",assurance:"mfa"}],emptyTitle:"No mail domains",emptyBody:"Add a domain and configure its mailbox and DNS policy."
  },
  mailQueue: {
    id:"mailQueue",title:"Mail queue & delivery",description:"Queued messages, delivery events, retries, policy decisions, and per-mailbox logs.",resourceKind:"mail.queue",listOperation:"mail.queue.list",
    columns:[{key:"queue_id",label:"Queue ID"},{key:"sender",label:"Sender"},{key:"recipients",label:"Recipients"},{key:"size",label:"Size",format:"bytes"},{key:"age",label:"Age",format:"duration"},{key:"status",label:"Status",format:"status"}],
    rowActions:[{id:"retry",label:"Retry",operation:"mail.queue.retry",mutating:true},{id:"inspect",label:"Inspect",operation:"mail.queue.inspect",mutating:false},{id:"delete",label:"Delete",operation:"mail.queue.delete",mutating:true,tone:"critical",assurance:"mfa"}],globalActions:[{id:"flush",label:"Flush queue",operation:"mail.queue.flush",mutating:true}],emptyTitle:"Mail queue is empty",emptyBody:"No messages are waiting for delivery."
  },
  webmail: {
    id:"webmail",title:"Webmail",description:"Mailbox folders, bounded search, messages, attachments, drafts, contacts, groups, and Sieve rules.",resourceKind:"mail.message",listOperation:"webmail.message.list",
    createAction:{id:"compose",label:"Compose",operation:"webmail.message.send",mutating:true,fields:[{key:"mailbox_id",label:"From mailbox",type:"text",required:true},{key:"to",label:"Recipients",type:"textarea",required:true},{key:"subject",label:"Subject",type:"text",required:true},{key:"text",label:"Message",type:"textarea",required:true}]},
    columns:[{key:"from",label:"From"},{key:"subject",label:"Subject"},{key:"received_at",label:"Received",format:"date"},{key:"size",label:"Size",format:"bytes"},{key:"flags",label:"Flags"},{key:"has_attachments",label:"Attachments",format:"status"}],
    rowActions:[{id:"read",label:"Read",operation:"webmail.message.get",mutating:false},{id:"reply",label:"Reply",operation:"webmail.message.reply",mutating:true},{id:"move",label:"Move",operation:"webmail.message.move",mutating:true},{id:"delete",label:"Delete",operation:"webmail.message.delete",mutating:true,tone:"critical"}],globalActions:[{id:"contacts",label:"Contacts",operation:"webmail.contact.list",mutating:false},{id:"rules",label:"Sieve rules",operation:"webmail.sieve.list",mutating:false}],emptyTitle:"No messages",emptyBody:"This folder does not contain any messages."
  },
  marketing: {
    id:"marketing",title:"Mail campaigns",description:"Consent-backed lists, subscribers, templates, delivery attempts, bounces, and immutable suppression.",resourceKind:"marketing.campaign",listOperation:"marketing.campaign.list",
    createAction:{id:"campaign",label:"Create campaign",operation:"marketing.campaign.create",mutating:true,fields:[{key:"list_id",label:"Audience list",type:"text",required:true},{key:"subject",label:"Subject",type:"text",required:true},{key:"template_ref",label:"Approved template version",type:"text",required:true},{key:"from_mailbox",label:"Sender mailbox",type:"text",required:true},{key:"reply_to",label:"Reply-to address",type:"email"},{key:"schedule",label:"Schedule",type:"cron"}]},
    columns:[{key:"name",label:"Campaign"},{key:"list",label:"Audience"},{key:"state",label:"State",format:"status"},{key:"recipients",label:"Recipients",format:"number"},{key:"delivered",label:"Delivered",format:"number"},{key:"updated_at",label:"Updated",format:"date"}],
    rowActions:[{id:"inspect",label:"Delivery attempts",operation:"marketing.attempt.list",mutating:false},{id:"approve",label:"Approve & freeze recipients",operation:"marketing.campaign.approve",mutating:true,assurance:"phishing_resistant",tone:"healthy",confirmation:"Approval freezes the current verified, consent-backed recipient set. Later list changes cannot expand this campaign."},{id:"start",label:"Start",operation:"marketing.campaign.start",mutating:true,assurance:"mfa"},{id:"pause",label:"Pause",operation:"marketing.campaign.pause",mutating:true,tone:"warning"},{id:"cancel",label:"Cancel",operation:"marketing.campaign.cancel",mutating:true,tone:"critical"}],globalActions:[{id:"templates",label:"Templates",operation:"marketing.template.list",mutating:false},{id:"audiences",label:"Lists & consent",operation:"marketing.list.list",mutating:false},{id:"subscribers",label:"Subscribers",operation:"marketing.subscriber.list",mutating:false},{id:"suppressions",label:"Suppressions",operation:"marketing.suppression.list",mutating:false}],emptyTitle:"No campaigns",emptyBody:"Create a campaign only after importing or collecting evidenced consent."
  },
  marketingTemplates: {
    id:"marketingTemplates",title:"Campaign templates",description:"Immutable, approved plain-text templates with safe recipient variables and one-click unsubscribe injection.",resourceKind:"marketing.template",listOperation:"marketing.template.list",detailOperation:"marketing.template.get",
    createAction:{id:"create",label:"Create template",operation:"marketing.template.create",mutating:true,fields:[{key:"name",label:"Template name",type:"text",required:true},{key:"text",label:"Message body",type:"textarea",required:true,helper:"Allowed variables: {{email}}, {{contact_id}}, and {{unsubscribe_url}}."}]},
    columns:[{key:"name",label:"Template"},{key:"state",label:"State",format:"status"},{key:"generation",label:"Version",format:"number"},{key:"updated_at",label:"Updated",format:"date"}],
    rowActions:[{id:"revise",label:"Create revision",operation:"marketing.template.update",mutating:true,fields:[{key:"name",label:"Template name",type:"text",required:true},{key:"text",label:"Message body",type:"textarea",required:true}]},{id:"approve",label:"Approve version",operation:"marketing.template.approve",mutating:true,assurance:"phishing_resistant",tone:"healthy",confirmation:"Approval freezes this exact template generation for campaign use."},{id:"archive",label:"Archive",operation:"marketing.template.archive",mutating:true,tone:"warning"}],emptyTitle:"No campaign templates",emptyBody:"Create a safe template, inspect it, then approve the exact version before campaign composition."
  },
  marketingSubscribers: {
    id:"marketingSubscribers",title:"Marketing subscribers",description:"Tenant-scoped recipients with deduplicated addresses, verification provenance, consent, tags, and lifecycle controls.",resourceKind:"marketing.subscriber",listOperation:"marketing.subscriber.list",detailOperation:"marketing.subscriber.get",
    createAction:{id:"create",label:"Add subscriber",operation:"marketing.subscriber.create",mutating:true,fields:[{key:"address",label:"Email address",type:"email",required:true},{key:"name",label:"Name",type:"text"},{key:"tags",label:"Tags",type:"text",helper:"Comma-separated opaque tags. Consent is recorded separately and is never inferred from this action."}]},
    columns:[{key:"address",label:"Address"},{key:"name",label:"Name"},{key:"tags",label:"Tags"},{key:"state",label:"State",format:"status"},{key:"verification",label:"Verification",format:"status"},{key:"generation",label:"Generation",format:"number"}],
    rowActions:[{id:"update",label:"Update",operation:"marketing.subscriber.update",mutating:true,fields:[{key:"address",label:"Email address",type:"email",required:true},{key:"name",label:"Name",type:"text"},{key:"tags",label:"Tags",type:"text"}]},{id:"verify",label:"Record verification",operation:"marketing.subscriber.verify",mutating:true,fields:[{key:"state",label:"Result",type:"select",required:true,options:[{label:"Verified",value:"verified"},{label:"Invalid",value:"invalid"},{label:"Risky",value:"risky"},{label:"Unknown",value:"unknown"}]},{key:"evidence_ref",label:"Evidence reference",type:"text",required:true}]},{id:"archive",label:"Archive",operation:"marketing.subscriber.archive",mutating:true,tone:"warning"},{id:"restore",label:"Restore",operation:"marketing.subscriber.restore",mutating:true},{id:"delete",label:"Delete archived subscriber",operation:"marketing.subscriber.delete",mutating:true,tone:"critical",assurance:"phishing_resistant",confirmation:"The subscriber must already be archived. Consent and suppression evidence remains retained under policy."}],emptyTitle:"No subscribers",emptyBody:"Add recipients, verify their addresses, and record affirmative consent before adding them to a sendable list."
  },
  containers: {
    id:"containers",title:"Containers",description:"Images, workloads, volumes, networks, exposures, health, logs, and constrained exec.",resourceKind:"container.workload",listOperation:"container.workload.list",
    createAction:{id:"create",label:"Create workload",operation:"container.workload.create",mutating:true,fields:[{key:"site_id",label:"Site",type:"text",required:true},{key:"image",label:"Image digest",type:"text",required:true},{key:"recipe",label:"Certified recipe",type:"text"},{key:"memory_bytes",label:"Memory limit",type:"number",required:true}]},
    columns:[{key:"name",label:"Workload"},{key:"image",label:"Image"},{key:"site",label:"Site"},{key:"state",label:"State",format:"status"},{key:"cpu",label:"CPU"},{key:"memory",label:"Memory",format:"bytes"}],
    rowActions:[{id:"restart",label:"Restart",operation:"container.workload.restart",mutating:true},{id:"logs",label:"Logs",operation:"container.logs.query",mutating:false},{id:"exec",label:"Exec",operation:"container.exec.issue",mutating:true,assurance:"mfa",confirmation:"This runs one allowlisted command inside the workload as its unprivileged runtime user.",fields:[{key:"command_id",label:"Command",type:"select",required:true,options:[{label:"Shell",value:"cmd_shell"},{label:"WP-CLI",value:"cmd_wp_cli"},{label:"PHP",value:"cmd_php"},{label:"Composer",value:"cmd_composer"}]},{key:"arguments",label:"Arguments (one per line)",type:"textarea",helper:"Each line is passed as one literal argument. Shell syntax is not interpreted by the panel."},{key:"ttl_seconds",label:"Grant lifetime (seconds)",type:"number",required:true,defaultValue:60}]},{id:"delete",label:"Delete",operation:"container.workload.delete",mutating:true,tone:"critical"}],emptyTitle:"No container workloads",emptyBody:"Deploy a signed recipe or constrained digest-pinned workload."
  },
  security: {
    id:"security",title:"Security posture",description:"Firewall, SSH, WAF, malware findings, quarantine, login activity, and repairs.",resourceKind:"security.finding",listOperation:"security.finding.list",
    columns:[{key:"severity",label:"Severity",format:"status"},{key:"kind",label:"Finding"},{key:"resource",label:"Resource"},{key:"source",label:"Source"},{key:"observed_at",label:"Observed",format:"date"},{key:"state",label:"State",format:"status"}],
    rowActions:[{id:"inspect",label:"Inspect",operation:"security.finding.get",mutating:false},{id:"remediate",label:"Remediate",operation:"security.remediation.apply",mutating:true,assurance:"mfa"},{id:"suppress",label:"Suppress",operation:"security.finding.suppress",mutating:true}],globalActions:[{id:"scan",label:"Run host scan",operation:"security.scan.start",mutating:true,tone:"info"}],emptyTitle:"No active findings",emptyBody:"Current policy checks and scanners have no unresolved findings."
  },
  services: {
    id:"services",title:"Services & diagnostics",description:"Managed service health, lifecycle, dependency diagnostics, repairs, metrics, and logs.",resourceKind:"operations.service",listOperation:"operations.service.list",
    columns:[{key:"name",label:"Service"},{key:"state",label:"State",format:"status"},{key:"health",label:"Health",format:"status"},{key:"version",label:"Version"},{key:"uptime",label:"Uptime",format:"duration"},{key:"updated_at",label:"Observed",format:"date"}],
    rowActions:[{id:"restart",label:"Restart",operation:"operations.service.restart",mutating:true},{id:"diagnose",label:"Diagnose",operation:"operations.diagnostic.run",mutating:true},{id:"logs",label:"Logs",operation:"operations.logs.query",mutating:false},{id:"stop",label:"Stop",operation:"operations.service.stop",mutating:true,tone:"critical",assurance:"mfa"}],emptyTitle:"No service projection",emptyBody:"Service discovery has not completed."
  },
  fleet: {
    id:"fleet",title:"Fleet & high availability",description:"Optional central enrollment, node health, placement, replication, fencing, and promotion.",resourceKind:"fleet.node",listOperation:"fleet.node.list",
    createAction:{id:"enroll",label:"Enroll node",operation:"fleet.node.enroll",mutating:true,assurance:"mfa",fields:[{key:"enrollment_token",label:"One-time enrollment token",type:"password",required:true},{key:"central_fingerprint",label:"Central CA fingerprint",type:"text",required:true}]},
    columns:[{key:"name",label:"Node"},{key:"state",label:"State",format:"status"},{key:"engine",label:"Engine"},{key:"sites",label:"Sites",format:"number"},{key:"pressure",label:"Pressure",format:"status"},{key:"last_seen",label:"Last seen",format:"date"}],
    rowActions:[{id:"details",label:"Details",operation:"fleet.node.get",mutating:false},{id:"drain",label:"Drain",operation:"ha.node.drain",mutating:true},{id:"promote",label:"Promotion plan",operation:"ha.promotion.plan",mutating:true,assurance:"phishing_resistant"},{id:"revoke",label:"Revoke",operation:"fleet.node.revoke",mutating:true,tone:"critical",assurance:"phishing_resistant"}],emptyTitle:"Standalone mode",emptyBody:"This node remains fully operational without a central control plane."
  },
  migrations: {
    id:"migrations",title:"Migrations",description:"Inventories, dry runs, mappings, chunk transfer, quiesce, cutover, verification, and rollback frontiers.",resourceKind:"migration.run",listOperation:"migration.list",
    createAction:{id:"create",label:"New migration",operation:"migration.create",mutating:true,fields:[{key:"source",label:"Source",type:"select",required:true,options:[{label:"CyberPanel",value:"cyberpanel"},{label:"cPanel archive",value:"cpanel"},{label:"Canonical manifest",value:"canonical"}]},{key:"source_endpoint",label:"Approved source",type:"text",required:true}]},
    columns:[{key:"id",label:"Migration"},{key:"source",label:"Source"},{key:"phase",label:"Phase",format:"status"},{key:"progress",label:"Progress"},{key:"updated_at",label:"Updated",format:"date"},{key:"rollback_deadline",label:"Rollback deadline",format:"date"}],
    rowActions:[{id:"inventory",label:"Inventory",operation:"migration.inventory",mutating:true},{id:"dryrun",label:"Dry run",operation:"migration.plan",mutating:true},{id:"sync",label:"Base sync",operation:"migration.sync",mutating:true,fields:[{key:"maximum_bytes",label:"Transfer byte ceiling (0 = planned size)",type:"number"}]},{id:"cutover",label:"Cut over",operation:"migration.cutover",mutating:true,tone:"warning",assurance:"phishing_resistant",fields:[{key:"approval_ref",label:"Approved change reference",type:"text",required:true}]}],emptyTitle:"No migrations",emptyBody:"Create a one-way source inventory without installing compatibility code."
  },
  users: {
    id:"users",title:"Users, tenants & plans",description:"Principals, memberships, reseller delegation ceilings, roles, plans, quotas, and suspension.",resourceKind:"identity.tenant",listOperation:"identity.tenant.list",
    createAction:{id:"tenant",label:"Create tenant",operation:"identity.tenant.create",mutating:true,fields:[{key:"name",label:"Tenant name",type:"text",required:true},{key:"parent_tenant_id",label:"Sponsoring tenant",type:"text"},{key:"plan_id",label:"Plan",type:"text",required:true}]},
    columns:[{key:"name",label:"Tenant"},{key:"kind",label:"Type"},{key:"members",label:"Members",format:"number"},{key:"sites",label:"Sites",format:"number"},{key:"quota",label:"Quota"},{key:"state",label:"State",format:"status"}],
    rowActions:[{id:"members",label:"Members",operation:"identity.membership.list",mutating:false},{id:"roles",label:"Roles",operation:"identity.role_binding.list",mutating:false},{id:"quota",label:"Plan & quotas",operation:"identity.entitlement.configure",mutating:true},{id:"suspend",label:"Suspend",operation:"identity.tenant.suspend",mutating:true,tone:"warning",assurance:"mfa"}],emptyTitle:"No delegated tenants",emptyBody:"The installation owner is currently the only tenant."
  },
  engines: {
    id:"engines",title:"Web engines & PHP",description:"OpenLiteSpeed, LiteSpeed Enterprise licensing/conversion, global tuning, and PHP profiles.",resourceKind:"webengine.installation",listOperation:"webengine.installation.list",
    columns:[{key:"edition",label:"Edition"},{key:"version",label:"Version"},{key:"license",label:"License",format:"status"},{key:"workers",label:"Workers",format:"number"},{key:"connections",label:"Connections",format:"number"},{key:"health",label:"Health",format:"status"}],
    rowActions:[{id:"license",label:"License",operation:"webengine.license.configure",mutating:true,assurance:"mfa"},{id:"convert",label:"Convert edition",operation:"webengine.convert",mutating:true,tone:"warning",assurance:"phishing_resistant"},{id:"tune",label:"Global tuning",operation:"webengine.tuning.configure",mutating:true},{id:"upgrade",label:"Upgrade",operation:"webengine.upgrade",mutating:true,assurance:"mfa"}],globalActions:[{id:"php",label:"Add PHP profile",operation:"webengine.php_profile.create",mutating:true}],emptyTitle:"No engine installation",emptyBody:"The web engine has not been initialized."
  },
  integrations: {
    id:"integrations",title:"Integrations",description:"DNS, storage, relay, security, registry, notification, and automation provider bindings.",resourceKind:"integration.binding",listOperation:"integration.binding.list",
    createAction:{id:"create",label:"Add integration",operation:"integration.binding.create",mutating:true,fields:[{key:"provider",label:"Provider",type:"select",required:true,options:[{label:"Cloudflare",value:"cloudflare"},{label:"AWS S3",value:"aws_s3"},{label:"Wasabi",value:"wasabi_s3"},{label:"Backblaze B2",value:"backblaze_b2_s3"}]},{key:"name",label:"Display name",type:"text",required:true},{key:"credential",label:"Credential",type:"password",required:true}]},
    columns:[{key:"name",label:"Integration"},{key:"provider",label:"Provider"},{key:"purpose",label:"Purpose"},{key:"state",label:"State",format:"status"},{key:"health",label:"Health",format:"status"},{key:"updated_at",label:"Checked",format:"date"}],
    rowActions:[{id:"test",label:"Test",operation:"integration.binding.health",mutating:true},{id:"rotate",label:"Rotate credential",operation:"integration.binding.rotate",mutating:true,assurance:"mfa"},{id:"delete",label:"Remove",operation:"integration.binding.delete",mutating:true,tone:"critical"}],emptyTitle:"No integrations",emptyBody:"The local node has no external provider bindings."
  },
  audit: {
    id:"audit",title:"Audit & activity",description:"Mutation decisions, privileged effects, secret delivery, sensitive reads, denials, and integrity checkpoints.",resourceKind:"audit.event",listOperation:"audit.event.query",
    columns:[{key:"occurred_at",label:"Time",format:"date"},{key:"actor",label:"Actor"},{key:"action",label:"Action"},{key:"resource",label:"Resource"},{key:"decision",label:"Decision",format:"status"},{key:"event_id",label:"Event ID"}],
    globalActions:[{id:"export",label:"Export evidence",operation:"audit.export",mutating:true,assurance:"mfa"},{id:"verify",label:"Verify chain",operation:"audit.verify",mutating:true}],emptyTitle:"No audit events",emptyBody:"No admitted security or control decisions match the current filters."
  }
};

export const navigation: NavigationGroup[] = [
  {id:"home",label:"Overview",items:[{id:"dashboard",label:"Overview",route:"/",icon:"Gauge",pageId:"dashboard",keywords:["health","summary","usage"]}]},
  {id:"hosting",label:"Hosting",items:[
    {id:"sites",label:"Sites",route:"/sites",icon:"GlobeHemisphereWest",pageId:"sites",keywords:["website","php","domain"]},
    {id:"domains",label:"Domains & routes",route:"/domains",icon:"Signpost",pageId:"domains",keywords:["alias","redirect","child"]},
    {id:"wordpress",label:"Applications",route:"/applications",icon:"Package",pageId:"wordpress",keywords:["wordpress","joomla","prestashop","mautic","magento","staging"]}
  ]},
  {id:"data",label:"Data & access",items:[
    {id:"databases",label:"Databases",route:"/databases",icon:"Database",pageId:"databases",keywords:["mariadb","mysql","grants"]},
    {id:"files",label:"Files & deploy",route:"/files",icon:"FolderOpen",pageId:"files",keywords:["file manager","git","upload"]},
    {id:"access",label:"FTP, SSH & terminal",route:"/access",icon:"TerminalWindow",pageId:"access",keywords:["sftp","key","shell"]},
    {id:"backups",label:"Backup & recovery",route:"/backups",icon:"Lifebuoy",pageId:"backups",keywords:["restore","retention","s3"]}
  ]},
  {id:"network",label:"Network & trust",items:[
    {id:"dns",label:"DNS",route:"/dns",icon:"TreeStructure",pageId:"dns",keywords:["powerdns","records","dnssec"]},
    {id:"certificates",label:"Certificates",route:"/certificates",icon:"Certificate",pageId:"certificates",keywords:["acme","tls","ssl"]},
    {id:"security",label:"Security posture",route:"/security",icon:"ShieldCheck",pageId:"security",keywords:["firewall","waf","scanner","ssh"]}
  ]},
  {id:"mail",label:"Mail",items:[
    {id:"mail",label:"Domains & mailboxes",route:"/mail",icon:"EnvelopeSimple",pageId:"mail",keywords:["postfix","dovecot","dkim"]},
    {id:"webmail",label:"Webmail",route:"/webmail",icon:"Tray",pageId:"webmail",keywords:["inbox","message","contacts","sieve"]},
    {id:"queue",label:"Queue & delivery",route:"/mail/queue",icon:"PaperPlaneTilt",pageId:"mailQueue",keywords:["smtp","delivery","logs"]},
    {id:"marketing",label:"Campaigns",route:"/mail/campaigns",icon:"Megaphone",pageId:"marketing",keywords:["lists","consent","unsubscribe","bounce"]},
    {id:"marketing-templates",label:"Campaign templates",route:"/mail/templates",icon:"Article",pageId:"marketingTemplates",keywords:["campaign","template","unsubscribe"]},
    {id:"marketing-subscribers",label:"Subscribers",route:"/mail/subscribers",icon:"AddressBook",pageId:"marketingSubscribers",keywords:["recipient","consent","verification","tags"]}
  ]},
  {id:"runtime",label:"Runtime & fleet",items:[
    {id:"containers",label:"Containers",route:"/containers",icon:"Cube",pageId:"containers",keywords:["docker","image","volume"]},
    {id:"services",label:"Services & diagnostics",route:"/services",icon:"Pulse",pageId:"services",keywords:["logs","metrics","redis"]},
    {id:"fleet",label:"Fleet & HA",route:"/fleet",icon:"Stack",pageId:"fleet",keywords:["central","cluster","replication"]},
    {id:"migrations",label:"Migrations",route:"/migrations",icon:"ArrowsLeftRight",pageId:"migrations",keywords:["cyberpanel","cpanel","cutover"]}
  ]},
  {id:"system",label:"System",items:[
    {id:"users",label:"Users & tenants",route:"/users",icon:"UsersThree",pageId:"users",keywords:["reseller","role","quota"]},
    {id:"engines",label:"Engines & PHP",route:"/engines",icon:"SlidersHorizontal",pageId:"engines",keywords:["ols","litespeed enterprise","license"]},
    {id:"integrations",label:"Integrations",route:"/integrations",icon:"PlugsConnected",pageId:"integrations",keywords:["cloudflare","s3","smtp"]},
    {id:"audit",label:"Audit & activity",route:"/audit",icon:"ListMagnifyingGlass",pageId:"audit",keywords:["events","evidence","history"]}
  ]}
];

export function pageForPath(path: string): PageDefinition {
  const item = navigation.flatMap((group) => group.items).find((candidate) => candidate.route === path);
  return pages[item?.pageId ?? "dashboard"] ?? pages.dashboard!;
}
