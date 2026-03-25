# Zeek Configuration for CHRONOS
# Network monitoring and detection

# Load scripts
@load policy/frameworks/cluster
@load policy/frameworks/dpd
@load policy/frameworks/files/hash-all-files
@load policy/frameworks/notice

# Enable logging
redef LogAscii::use_json = T;
redef Log::default_rotation_interval = 1hr;

# Notice configuration
redef Notice::should_email = F;
redef Notice::should_notice = function(n: Notice::Info): bool {
    # Don't alert on local traffic
    if (Site::is_local_addr(n$id$orig_h) && Site::is_local_addr(n$id$resp_h))
        return T;
    return F;
};

# Suspicious DNS
redef dns_active = T;

# Detect DNS tunneling
module DNS;
redef ttl_threshold = 300;

# HTTP logging
redef HTTP::default_capture_password = T;
redef HTTP::log_all_hostnames = T;

# SSL/TLS logging
redef SSL::default_capture_cert = T;
redef SSL::log_certs = T;

# Connection logging
redef conn_log_path = "conn";
redef conn_log_interval = 1hr;

# Files
redef files_log_path = "files";

# Notice types to alert on
module Notice;

# SSH bruteforce
event ssh_auth_successful(c: connection, auth_method: string)
{
    NOTICE([$note=Suspicious,
            $msg=fmt("SSH authentication to %s", c$id$resp_h),
            $conn=c,
            $identifier=cat(c$id$orig_h,c$id$resp_h)]);
}

event ssh_auth_failed(c: connection, auth_method: string)
{
    NOTICE([$note=Suspicious,
            $msg=fmt("SSH failed auth to %s from %s", c$id$resp_h, c$id$orig_h),
            $conn=c,
            $identifier=cat(c$id$orig_h,c$id$resp_h)]);
}

# Detect software
event software_version_found(c: connection, software: Software::Info)
{
    if ( /bind/i in software$software_type || /openssh/i in software$software_type )
        print fmt("Found software: %s on %s", software$software_type, c$id$resp_h);
}
