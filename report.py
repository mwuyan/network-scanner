import json
import sys
import texttable
from collections import Counter


def create_report(input_f, output_f):
    with open(input_f) as json_file:
        scan = json.load(json_file)

    with open(output_f, "w") as text_file:
        text_file.write(complete_table(scan).draw() + '\n\n')
        text_file.write(rtt_table(scan).draw() + '\n\n')
        text_file.write(root_ca_table(scan).draw() + '\n\n')
        text_file.write(web_server_table(scan).draw() + '\n\n')
        text_file.write(domain_support_table(scan).draw())


def complete_table(scan):
    table = texttable.Texttable()
    headers = ['scan_time', 'ipv4_addresses', 'ipv6_addresses', 'http_server', 'insecure_http', 'redirect_to_https',
               'hsts', 'tls_versions', 'root_ca', 'rdns_names', 'rtt_range', 'geo_locations']
    table.header(['domain'] + headers)
    table.set_max_width(200)
    table.set_cols_dtype(['a', 'f', 'a', 'a', 'a', 't', 't', 't', 'a', 'a', 'a', 'a', 'a'])
    for domain in scan:
        row = [domain]
        for info in headers:
            row.append(scan[domain].get(info))
        table.add_row(row)
    return table


def rtt_table(scan):
    table = texttable.Texttable()
    table.header(['domain', 'rtt'])
    table.set_max_width(200)
    times = []
    for domain in scan:
        times.append([domain, scan[domain].get('rtt_range')])
    final = sorted(times, key=lambda lis: lis[1])
    table.add_rows(final, header=False)
    return table


def root_ca_table(scan):
    table = texttable.Texttable()
    table.header(['root certificate authority', 'frequency'])
    table.set_max_width(200)
    certificates = []
    for domain in scan:
        certificates.append(scan[domain].get('root_ca'))
    frequency = Counter(certificates)
    rows = []
    for counts in frequency.items():
        rows.append([counts[0], counts[1]])
    final = sorted(rows, key=lambda lis: lis[1], reverse=True)
    table.add_rows(final, header=False)
    return table


def web_server_table(scan):
    table = texttable.Texttable()
    table.header(['web server', 'frequency'])
    table.set_max_width(200)
    servers = []
    for domain in scan:
        servers.append(scan[domain].get('http_server'))
    frequency = Counter(servers)
    rows = []
    for counts in frequency.items():
        rows.append([counts[0], counts[1]])
    final = sorted(rows, key=lambda lis: lis[1], reverse=True)
    table.add_rows(final, header=False)
    return table


def domain_support_table(scan):
    count = {'TLSv1.0': 0, 'TLSv1.1': 0, 'TLSv1.2': 0, 'TLSv1.3': 0, 'SSLv2': 0, 'SSLv3': 0,
             'insecure_http': 0, 'redirect_to_https': 0, 'hsts': 0, 'ipv6_addresses': 0}
    features = ['ipv6_addresses', 'insecure_http', 'redirect_to_https', 'hsts', 'tls_versions']
    table = texttable.Texttable()
    table.header(['feature', 'domains that support (%)'])
    table.set_max_width(200)
    for domain in scan:
        for i in features:
            result = scan[domain].get(i)
            if result is True:
                count[i] = count[i] + 1
            elif i is 'tls_versions':
                for j in result:
                    count[j] = count[j] + 1
            elif i is 'ipv6_addresses':
                if result:
                    count[i] = count[i] + 1
    rows = []
    num_domain = float(len(scan))
    for feat in count:
        row = [feat, '{:.1%}'.format(count[feat] / num_domain)]
        if feat == 'insecure_http':
            row[0] = 'plain http'
        elif feat == 'redirect_to_https':
            row[0] = 'https redirect'
        elif feat == 'ipv6_addresses':
            row[0] = 'ipv6'
        rows.append(row)
    table.add_rows(rows, header=False)
    return table


if __name__ == "__main__":
    inputs = sys.argv
    create_report(inputs[1], inputs[2])
