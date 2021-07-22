import json
import sys
import time
import subprocess
import http.client
import requests
import maxminddb



def scan(input_f, output_f):
    public_dns_resolvers = ['208.67.222.222', '1.1.1.1', '8.8.8.8', '8.26.56.26', '9.9.9.9', '64.6.65.6',
                            '91.239.100.100','185.228.168.168', '77.88.8.7', '156.154.70.1',
                            '198.101.242.72', '176.103.130.130']
    with open(input_f) as f:
        websites = [line.rstrip() for line in f]

    scan_results = {}
    for i in websites:
        scan_results[i] = scanners(i,public_dns_resolvers)

    with open(output_f, "w") as f:
        json.dump(scan_results, f, sort_keys=True, indent=4)


def scanners(website,dns):
    scans = {"scan_time": time.time(), "ipv4_addresses": ipv4(website, dns), "ipv6_addresses": ipv6(website, dns)}
    if not scans["ipv6_addresses"] and not scans["ipv4_addresses"]:
        return scans
    else:
        scans["insecure_http"], scans["redirect_to_https"] = http_server(website)
        scans["http_server"], scans["hsts"] = https_server(website)
        scans["tls_versions"] = tls_versions(website)
        scans["root_ca"] = root_ca(website)
        scans["rdns_names"] = rdns_names(scans["ipv4_addresses"])
        scans["rtt_range"] = rtt_range(scans["ipv4_addresses"])
        scans["geo_locations"] = geo_locations(scans["ipv4_addresses"])
        return scans


def ipv4(website,dns):
    addresses = []
    for i in dns:
        count = 0
        while count < 5:
            try:
                result = subprocess.check_output(["nslookup", "-type=A", website, i],
                                                 timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
                if "No answer" in result or "NXDOMAIN" in result:
                    break
                answer = result[result.find("Name:"):] \
                    .strip().replace("\n", " ").replace("\t", " ")
                answer = answer.split(" ")
                for j in range(1, len(answer)):
                    if answer[j - 1] == 'Address:' and answer[j] not in addresses:
                        addresses.append(answer[j])
                break
            except subprocess.CalledProcessError as e:
                count += 1
                continue
            except Exception as e:
                print('ipv4 error')
                print(e)
                count += 1
                continue
    return addresses


def ipv6(website,dns):
    addresses = []
    for i in dns:
        count = 0
        while count < 5:
            try:
                result = subprocess.check_output(["nslookup", "-type=AAAA", website, i],
                                                 timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
                if "No answer" in result or "NXDOMAIN" in result:
                    break
                answer = result[result.find("Name"):] \
                    .strip().replace("\n", " ").replace("\t", " ")
                answer = answer.split(" ")
                for j in range(1, len(answer)):
                    if answer[j - 1] == 'Address:' and answer[j] not in addresses:
                        addresses.append(answer[j])
                break
            except subprocess.CalledProcessError as e:
                count += 1
                continue
            except Exception as e:
                print('ipv6 error')
                print(e)
                count += 1
                continue
    return addresses


def http_server(website):
    try:
        connection = http.client.HTTPConnection(website, 80, timeout=10)
        connection.request("GET", "/")
        response = connection.getresponse()
        connection.close()
        if 'Location' in response.headers:
            return True, check_for_redirect(response.getheader('Location'), 0)
        else:
            return True, False
    except Exception as e:
        print('http server error')
        print(e)
    return False, False


def https_server(website):
    try:
        connection = http.client.HTTPSConnection(website, timeout=10)
        connection.request("GET", "/")
        response = connection.getresponse()
        connection.close()
        if response.status == 200:
            if response.headers.get('Strict-Transport-Security'):
                return response.headers.get('Server'), True
            else:
                return response.headers.get('Server'), False
        else:
            return get_final_headers(response.getheader('Location'), 0)
    except Exception as e:
        print('https server error')
        print(e)
        return None, False


def get_final_headers(website, count):
    try:
        r = requests.get(website, allow_redirects=False,timeout=10)
        if 300 <= r.status_code < 400:
            if count > 9:
                if 'Strict-Transport-Security' in r.headers:
                    return r.headers.get('Server'), True
                else:
                    return r.headers.get('Server'), False
            else:
                return get_final_headers(r.headers['Location'], count + 1)
        else:
            if 'Strict-Transport-Security' in r.headers:
                return r.headers.get('Server'), True
            else:
                return r.headers.get('Server'), False
    except Exception as e:
        print(e)
        return None, False


def check_for_redirect(website, count):
    try:
        if count > 9:
            return False
        r = requests.get(website, allow_redirects=False,timeout=10)
        if 'Location' in r.headers:
            if "https" in r.headers['Location']:
                return True
            else:
                return check_for_redirect(r.headers.get('Location'), count + 1)
        else:
            return False
    except Exception as e:
        print(e)
        return False


def tls_versions(website):
    supported = []
    try:
        result = subprocess.check_output(["nmap", "--script", "ssl-enum-ciphers", "-p", "443", website],
                                         timeout=10, stderr=subprocess.STDOUT).decode("utf-8")
        versions = ["TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3", "SSLv2"]
        for i in versions:
            if i in result:
                supported.append(i)
        try:
            updated_result = subprocess.check_output(["openssl", "s_client", "-tls1_3", "-connect", website + ":443"],
                                                     timeout=10, stderr=subprocess.STDOUT, input="").decode("utf-8")
            if "TLSv1.3" in updated_result:
                supported.append("TLSv1.3")
        except subprocess.CalledProcessError as e:
            if "TLSv1.3" in e.output.decode("utf-8"):
                supported.append("TLSv1.3")
        return supported
    except Exception as e:
        print('tls error')
        print(e)
        return supported


def root_ca(website):
    try:
        result = subprocess.check_output(["openssl", "s_client", "-connect", website + ":443"],
                                         timeout=10, stderr=subprocess.STDOUT, input="").decode("utf-8")
        cert = result[result.find("Certificate chain"):]
        cert = cert[:result.find("---")]
        position = cert.rindex("O =")
        cert = cert[position + 3:]
        return cert[:cert.find(",")].lstrip()
    except subprocess.CalledProcessError as e:
        return None
    except Exception as e:
        print('root ca error')
        print(e)
        return None


def rdns_names(addresses):
    names = []
    for i in addresses:
        try:
            result = subprocess.check_output(["nslookup", "-type=PTR", i],
                                             timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
            if "No answer" in result or "NXDOMAIN" in result:
                continue
            else:
                result = result[result.find("name = "):].replace("\n", " ").replace("\t", " ")
                result = result.split(" ")
                names.append(result[2][:-1])
        except subprocess.CalledProcessError as e:
            continue
        except Exception as e:
            print('rdns error')
            print(e)
            continue
    return names


def rtt_range(addresses):
    times = []
    for i in addresses:
        try:
            try:
                result = subprocess.check_output(["sh", "-c", "time echo -e '\x1dclose\x0d' | telnet " + i + " 443"],
                                                 timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
            except Exception as e:
                print(e)
                try:
                    result = subprocess.check_output(["sh", "-c", "time echo -e '\x1dclose\x0d' | telnet " + i + " 80"],
                                                     timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
                except Exception as e:
                    print(e)
                    try:
                        result = subprocess.check_output(
                            ["sh", "-c", "time echo -e '\x1dclose\x0d' | telnet " + i + " 80"],
                            timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
                    except Exception as e:
                        print(e)
                        continue
            result = result[result.find("real"):]
            result = result[:result.find("s")].split(".")
            times.append(float("." + result[1]) * 1000)
        except Exception as e:
            print('rtt error')
            print(e)
            continue
    return min(times), max(times)


def geo_locations(addresses):
    locations = []
    reader = maxminddb.open_database('GeoLite2-City.mmdb')
    for i in addresses:
        try:
            geo = reader.get(i)
            location = []
            location.append(geo.get('city', {}).get('names', {}).get('en'))
            subdivision = geo.get('subdivisions')
            if subdivision:
                location.append(subdivision[0].get('names', {}).get('en'))
            if 'country' not in geo:
                location.append(geo.get('continent', {}).get('names', {}).get('en'))
            else:
                location.append(geo.get('country', {}).get('names', {}).get('en'))
            result = ''
            for j in location:
                if result and j:
                    result = result + ', ' + j
                elif not result and j:
                    result = j
            if result and result not in locations:
                locations.append(result)
        except Exception as e:
            print('geo error')
            print(e)
            continue
    reader.close()
    return locations


if __name__ == "__main__":
    inputs = sys.argv
    scan(inputs[1], inputs[2])
