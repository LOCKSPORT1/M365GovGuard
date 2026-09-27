<#
    GENERATED FILE - do not edit by hand.

    Produced by Tools\Convert-ControlCatalog.ps1. Regenerate rather than
    editing; hand edits are lost on the next build and break provenance.
#>
@{

    Framework    = 'NIST SP 800-171'
    Revision     = 'Rev 2'
    ControlCount = 110

    Provenance = @{
        SourceUrl    = 'https://csrc.nist.gov/files/pubs/sp/800/171/r2/upd1/final/docs/sp800-171r2-security-reqs.csv'
        SourceFile   = 'nist-official.csv'
        SourceSha256 = '0F4D59413BBCC9998DA80495CE46EBFE0475E392803C4D2ED38D9941D83F138D'
        Retrieved    = '2026-09-25'
        Generator    = 'Convert-ControlCatalog.ps1 v1.0'
        InputFormat  = 'Csv'
    }

    Families = @(
        @{
            Id           = '3.1'
            Abbreviation = 'AC'
            Name         = 'Access Control'
            ControlCount = 22
            Controls     = @(
                @{ Id = '3.1.1'; Title = 'Limit system access to authorized users, processes acting on behalf of authorized users, and devices (including other systems).' }
                @{ Id = '3.1.2'; Title = 'Limit system access to the types of transactions and functions that authorized users are permitted to execute.' }
                @{ Id = '3.1.3'; Title = 'Control the flow of CUI in accordance with approved authorizations.' }
                @{ Id = '3.1.4'; Title = 'Separate the duties of individuals to reduce the risk of malevolent activity without collusion.' }
                @{ Id = '3.1.5'; Title = 'Employ the principle of least privilege, including for specific security functions and privileged accounts.' }
                @{ Id = '3.1.6'; Title = 'Use non-privileged accounts or roles when accessing nonsecurity functions' }
                @{ Id = '3.1.7'; Title = 'Prevent non-privileged users from executing privileged functions and capture the execution of such functions in audit logs.' }
                @{ Id = '3.1.8'; Title = 'Limit unsuccessful logon attempts.' }
                @{ Id = '3.1.9'; Title = 'Provide privacy and security notices consistent with applicable CUI rules.' }
                @{ Id = '3.1.10'; Title = 'Use session lock with pattern-hiding displays to prevent access and viewing of data after a period of inactivity' }
                @{ Id = '3.1.11'; Title = 'Terminate (automatically) a user session after a defined condition.' }
                @{ Id = '3.1.12'; Title = 'Monitor and control remote access sessions.' }
                @{ Id = '3.1.13'; Title = 'Employ cryptographic mechanisms to protect the confidentiality of remote access sessions.' }
                @{ Id = '3.1.14'; Title = 'Route remote access via managed access control points.' }
                @{ Id = '3.1.15'; Title = 'Authorize remote execution of privileged commands and remote access to security-relevant information.' }
                @{ Id = '3.1.16'; Title = 'Authorize wireless access prior to allowing such connections' }
                @{ Id = '3.1.17'; Title = 'Protect wireless access using authentication and encryption' }
                @{ Id = '3.1.18'; Title = 'Control connection of mobile devices.' }
                @{ Id = '3.1.19'; Title = 'Encrypt CUI on mobile devices and mobile computing platforms.[23]' }
                @{ Id = '3.1.20'; Title = 'Verify and control/limit connections to and use of external systems.' }
                @{ Id = '3.1.21'; Title = 'Limit use of portable storage devices on external systems.' }
                @{ Id = '3.1.22'; Title = 'Control CUI posted or processed on publicly accessible systems.' }
            )
        }

        @{
            Id           = '3.2'
            Abbreviation = 'AT'
            Name         = 'Awareness and Training'
            ControlCount = 3
            Controls     = @(
                @{ Id = '3.2.1'; Title = 'Ensure that managers, systems administrators, and users of organizational systems are made aware of the security risks associated with their activities and of the applicable policies, standards, and procedures related to the security of those systems.' }
                @{ Id = '3.2.2'; Title = 'Ensure that personnel are trained to carry out their assigned information security-related duties and responsibilities.' }
                @{ Id = '3.2.3'; Title = 'Provide security awareness training on recognizing and reporting potential indicators of insider threat.' }
            )
        }

        @{
            Id           = '3.3'
            Abbreviation = 'AU'
            Name         = 'Audit and Accountability'
            ControlCount = 9
            Controls     = @(
                @{ Id = '3.3.1'; Title = 'Create and retain system audit logs and records to the extent needed to enable the monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity' }
                @{ Id = '3.3.2'; Title = 'Ensure that the actions of individual system users can be uniquely traced to those users, so they can be held accountable for their actions.' }
                @{ Id = '3.3.3'; Title = 'Review and update logged events.' }
                @{ Id = '3.3.4'; Title = 'Alert in the event of an audit logging process failure.' }
                @{ Id = '3.3.5'; Title = 'Correlate audit record review, analysis, and reporting processes for investigation and response to indications of unlawful, unauthorized, suspicious, or unusual activity.' }
                @{ Id = '3.3.6'; Title = 'Provide audit record reduction and report generation to support on-demand analysis and reporting.' }
                @{ Id = '3.3.7'; Title = 'Provide a system capability that compares and synchronizes internal system clocks with an authoritative source to generate time stamps for audit records' }
                @{ Id = '3.3.8'; Title = 'Protect audit information and audit logging tools from unauthorized access, modification, and deletion.' }
                @{ Id = '3.3.9'; Title = 'Limit management of audit logging functionality to a subset of privileged users.' }
            )
        }

        @{
            Id           = '3.4'
            Abbreviation = 'CM'
            Name         = 'Configuration Management'
            ControlCount = 9
            Controls     = @(
                @{ Id = '3.4.1'; Title = 'Establish and maintain baseline configurations and inventories of organizational systems (including hardware, software, firmware, and documentation) throughout the respective system development life cycles.' }
                @{ Id = '3.4.2'; Title = 'Establish and enforce security configuration settings for information technology products employed in organizational systems.' }
                @{ Id = '3.4.3'; Title = 'Track, review, approve or disapprove, and log changes to organizational systems.' }
                @{ Id = '3.4.4'; Title = 'Analyze the security impact of changes prior to implementation.' }
                @{ Id = '3.4.5'; Title = 'Define, document, approve, and enforce physical and logical access restrictions associated with changes to organizational systems.' }
                @{ Id = '3.4.6'; Title = 'Employ the principle of least functionality by configuring organizational systems to provide only essential capabilities.' }
                @{ Id = '3.4.7'; Title = 'Restrict, disable, or prevent the use of nonessential programs, functions, ports, protocols, and services.' }
                @{ Id = '3.4.8'; Title = 'Apply deny-by-exception (blacklisting) policy to prevent the use of unauthorized software or deny-all, permit-by-exception (whitelisting) policy to allow the execution of authorized software.' }
                @{ Id = '3.4.9'; Title = 'Control and monitor user-installed software.' }
            )
        }

        @{
            Id           = '3.5'
            Abbreviation = 'IA'
            Name         = 'Identification and Authentication'
            ControlCount = 11
            Controls     = @(
                @{ Id = '3.5.1'; Title = 'Identify system users, processes acting on behalf of users, and devices.' }
                @{ Id = '3.5.2'; Title = 'Authenticate (or verify) the identities of users, processes, or devices, as a prerequisite to allowing access to organizational systems.' }
                @{ Id = '3.5.3'; Title = 'Use multifactor authentication for local and network access to privileged accounts and for network access to non-privileged accounts.[24] [25].' }
                @{ Id = '3.5.4'; Title = 'Employ replay-resistant authentication mechanisms for network access to privileged and non-privileged accounts.' }
                @{ Id = '3.5.5'; Title = 'Prevent reuse of identifiers for a defined period.' }
                @{ Id = '3.5.6'; Title = 'Disable identifiers after a defined period of inactivity.' }
                @{ Id = '3.5.7'; Title = 'Enforce a minimum password complexity and change of characters when new passwords are created.' }
                @{ Id = '3.5.8'; Title = 'Prohibit password reuse for a specified number of generations.' }
                @{ Id = '3.5.9'; Title = 'Allow temporary password use for system logons with an immediate change to a permanent password.' }
                @{ Id = '3.5.10'; Title = 'Store and transmit only cryptographically-protected passwords.' }
                @{ Id = '3.5.11'; Title = 'Obscure feedback of authentication information' }
            )
        }

        @{
            Id           = '3.6'
            Abbreviation = 'IR'
            Name         = 'Incident Response'
            ControlCount = 3
            Controls     = @(
                @{ Id = '3.6.1'; Title = 'Establish an operational incident-handling capability for organizational systems that includes preparation, detection, analysis, containment, recovery, and user response activities.' }
                @{ Id = '3.6.2'; Title = 'Track, document, and report incidents to designated officials and/or authorities both internal and external to the organization.' }
                @{ Id = '3.6.3'; Title = 'Test the organizational incident response capability.' }
            )
        }

        @{
            Id           = '3.7'
            Abbreviation = 'MA'
            Name         = 'Maintenance'
            ControlCount = 6
            Controls     = @(
                @{ Id = '3.7.1'; Title = 'Perform maintenance on organizational systems.[26].' }
                @{ Id = '3.7.2'; Title = 'Provide controls on the tools, techniques, mechanisms, and personnel used to conduct system maintenance.' }
                @{ Id = '3.7.3'; Title = 'Ensure equipment removed for off-site maintenance is sanitized of any CUI.' }
                @{ Id = '3.7.4'; Title = 'Check media containing diagnostic and test programs for malicious code before the media are used in organizational systems.' }
                @{ Id = '3.7.5'; Title = 'Require multifactor authentication to establish nonlocal maintenance sessions via external network connections and terminate such connections when nonlocal maintenance is complete.' }
                @{ Id = '3.7.6'; Title = 'Supervise the maintenance activities of maintenance personnel without required access authorization.' }
            )
        }

        @{
            Id           = '3.8'
            Abbreviation = 'MP'
            Name         = 'Media Protection'
            ControlCount = 9
            Controls     = @(
                @{ Id = '3.8.1'; Title = 'Protect (i.e., physically control and securely store) system media containing CUI, both paper and digital.' }
                @{ Id = '3.8.2'; Title = 'Limit access to CUI on system media to authorized users' }
                @{ Id = '3.8.3'; Title = 'Sanitize or destroy system media containing CUI before disposal or release for reuse.' }
                @{ Id = '3.8.4'; Title = 'Mark media with necessary CUI markings and distribution limitations.[27]' }
                @{ Id = '3.8.5'; Title = 'Control access to media containing CUI and maintain accountability for media during transport outside of controlled areas.' }
                @{ Id = '3.8.6'; Title = 'Implement cryptographic mechanisms to protect the confidentiality of CUI stored on digital media during transport unless otherwise protected by alternative physical safeguards.' }
                @{ Id = '3.8.7'; Title = 'Control the use of removable media on system components.' }
                @{ Id = '3.8.8'; Title = 'Prohibit the use of portable storage devices when such devices have no identifiable owner.' }
                @{ Id = '3.8.9'; Title = 'Protect the confidentiality of backup CUI at storage locations.' }
            )
        }

        @{
            Id           = '3.9'
            Abbreviation = 'PS'
            Name         = 'Personnel Security'
            ControlCount = 2
            Controls     = @(
                @{ Id = '3.9.1'; Title = 'Screen individuals prior to authorizing access to organizational systems containing CUI.' }
                @{ Id = '3.9.2'; Title = 'Ensure that organizational systems containing CUI are protected during and after personnel actions such as terminations and transfers' }
            )
        }

        @{
            Id           = '3.10'
            Abbreviation = 'PE'
            Name         = 'Physical Protection'
            ControlCount = 6
            Controls     = @(
                @{ Id = '3.10.1'; Title = 'Limit physical access to organizational systems, equipment, and the respective operating environments to authorized individuals.' }
                @{ Id = '3.10.2'; Title = 'Protect and monitor the physical facility and support infrastructure for organizational systems.' }
                @{ Id = '3.10.3'; Title = 'Escort visitors and monitor visitor activity.' }
                @{ Id = '3.10.4'; Title = 'Maintain audit logs of physical access.' }
                @{ Id = '3.10.5'; Title = 'Control and manage physical access devices.' }
                @{ Id = '3.10.6'; Title = 'Enforce safeguarding measures for CUI at alternate work sites.' }
            )
        }

        @{
            Id           = '3.11'
            Abbreviation = 'RA'
            Name         = 'Risk Assessment'
            ControlCount = 3
            Controls     = @(
                @{ Id = '3.11.1'; Title = 'Periodically assess the risk to organizational operations (including mission, functions, image, or reputation), organizational assets, and individuals, resulting from the operation of organizational systems and the associated processing, storage, or transmission of CUI' }
                @{ Id = '3.11.2'; Title = 'Scan for vulnerabilities in organizational systems and applications periodically and when new vulnerabilities affecting those systems and applications are identified.' }
                @{ Id = '3.11.3'; Title = 'Remediate vulnerabilities in accordance with risk assessments.' }
            )
        }

        @{
            Id           = '3.12'
            Abbreviation = 'CA'
            Name         = 'Security Assessment'
            ControlCount = 4
            Controls     = @(
                @{ Id = '3.12.1'; Title = 'Periodically assess the security controls in organizational systems to determine if the controls are effective in their application.' }
                @{ Id = '3.12.2'; Title = 'Develop and implement plans of action designed to correct deficiencies and reduce or eliminate vulnerabilities in organizational systems.' }
                @{ Id = '3.12.3'; Title = 'Monitor security controls on an ongoing basis to ensure the continued effectiveness of the controls.' }
                @{ Id = '3.12.4'; Title = 'Develop, document, and periodically update system security plans that describe system boundaries, system environments of operation, how security requirements are implemented, and the relationships with or connections to other systems.[28]' }
            )
        }

        @{
            Id           = '3.13'
            Abbreviation = 'SC'
            Name         = 'System and Communications Protection'
            ControlCount = 16
            Controls     = @(
                @{ Id = '3.13.1'; Title = 'Monitor, control, and protect communications (i.e., information transmitted or received by organizational systems) at the external boundaries and key internal boundaries of organizational systems.' }
                @{ Id = '3.13.2'; Title = 'Employ architectural designs, software development techniques, and systems engineering principles that promote effective information security within organizational systems.' }
                @{ Id = '3.13.3'; Title = 'Separate user functionality from system management functionality.' }
                @{ Id = '3.13.4'; Title = 'Prevent unauthorized and unintended information transfer via shared system resources.' }
                @{ Id = '3.13.5'; Title = 'Implement subnetworks for publicly accessible system components that are physically or logically separated from internal networks.' }
                @{ Id = '3.13.6'; Title = 'Deny network communications traffic by default and allow network communications traffic by exception (i.e., deny all, permit by exception).' }
                @{ Id = '3.13.7'; Title = 'Prevent remote devices from simultaneously establishing non-remote connections with organizational systems and communicating via some other connection to resources in external networks (i.e., split tunneling).' }
                @{ Id = '3.13.8'; Title = 'Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission unless otherwise protected by alternative physical safeguards.' }
                @{ Id = '3.13.9'; Title = 'Terminate network connections associated with communications sessions at the end of the sessions or after a defined period of inactivity.' }
                @{ Id = '3.13.10'; Title = 'Establish and manage cryptographic keys for cryptography employed in organizational systems.' }
                @{ Id = '3.13.11'; Title = 'Employ FIPS-validated cryptography when used to protect the confidentiality of CUI.' }
                @{ Id = '3.13.12'; Title = 'Prohibit remote activation of collaborative computing devices and provide indication of devices in use to users present at the device.[29].' }
                @{ Id = '3.13.13'; Title = 'Control and monitor the use of mobile code.' }
                @{ Id = '3.13.14'; Title = 'Control and monitor the use of Voice over Internet Protocol (VoIP) technologies.' }
                @{ Id = '3.13.15'; Title = 'Protect the authenticity of communications sessions.' }
                @{ Id = '3.13.16'; Title = 'Protect the confidentiality of CUI at rest.' }
            )
        }

        @{
            Id           = '3.14'
            Abbreviation = 'SI'
            Name         = 'System and Information Integrity'
            ControlCount = 7
            Controls     = @(
                @{ Id = '3.14.1'; Title = 'Identify, report, and correct system flaws in a timely manner.' }
                @{ Id = '3.14.2'; Title = 'Provide protection from malicious code at designated locations within organizational systems.' }
                @{ Id = '3.14.3'; Title = 'Monitor system security alerts and advisories and take action in response.' }
                @{ Id = '3.14.4'; Title = 'Update malicious code protection mechanisms when new releases are available.' }
                @{ Id = '3.14.5'; Title = 'Perform periodic scans of organizational systems and real-time scans of files from external sources as files are downloaded, opened, or executed.' }
                @{ Id = '3.14.6'; Title = 'Monitor organizational systems, including inbound and outbound communications traffic, to detect attacks and indicators of potential attacks.' }
                @{ Id = '3.14.7'; Title = 'Identify unauthorized use of organizational systems.' }
            )
        }

    )
}

