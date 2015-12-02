# encoding:utf-8

import sys
import re


def general_manage(data_result):
    domain_info = {}
    i = 0
    pattern = re.compile(
        r'(Registrant Phone:.*|Registrant Name:.*|Registrant Email:.*|Registrant E-mail:.*)')
    match = pattern.findall(data_result)
    match_length = len(match)
    if match:
        for i in range(match_length):
            if match[i].split(':')[0].strip() == 'Registrant Phone':
                domain_info['reg_phone'] = match[i].split(':')[1].strip()
            elif match[i].split(':')[0].strip() == 'Registrant Name':
                domain_info['reg_name'] = match[i].split(':')[1].strip()
            elif match[i].split(':')[0].strip() == 'Registrant Email':
                domain_info['reg_email'] = match[i].split(':')[1].strip()
            elif match[i].split(':')[0].strip() == 'Registrant E-mail':
                domain_info['reg_email'] = match[i].split(':')[1].strip()
            domain_info['detail'] = str(data_result)
        return domain_info
    else:
        return


def get_sec_server(data_result, query_domain):

    pattern = re.compile(r'Domain Name:.*|Whois Server:.*')
    match = pattern.findall(data_result)

    if match:
        length = len(match)
        for i in range(length):

            if match[i].lower().find(query_domain) != -1:

                try:
                    sec_whois_server = match[i + 1].split(':')[1].strip()
                    return sec_whois_server
                except:
                    print 'Something Else Wrong'
                    return


def xxx_manage(data_result):

    pattern_other = re.compile(r'xxx')
    match_other = pattern_other.search(str(data_result))

    if match_other:
        return True
    else:
        return False


def no_match(data_result):
    domain_info = {}
    pattern_no = re.compile(r'No match')
    match = pattern_no.search(data_result)
    if match:
        print 'NoMatch'
        domain_info['reg_name'] = 'NoMatch'
    domain_info['detail'] = data_result
    return domain_info



def ua_manage(data_result):
    domain_info = {}

    domain_info['detail'] = str(data_result)
    return domain_info


def ie_manage(data_result):

    domain_info = {}
    pattern = re.compile(r'(person:.*)')
    match = pattern.findall(data_result)
    print match
    if match:
        domain_info['reg_name'] = match[0].split(':')[1].strip()
    domain_info['detail'] = str(data_result)
    return domain_info


def es_manage(data_result):
    domain_info = {}
    domain_info['detail'] = str(data_result)
    return domain_info


def ru_manage(data_result):

    domain_info = {}
    pattern = re.compile(r'(person:.*|registrar:.*)')
    match = pattern.findall(data_result)
    print match
    if match:
        domain_info['reg_name'] = match[0].split(':')[1].strip()
    domain_info['detail'] = data_result
    return domain_info


def nomatch_manage(data_result):
    domain_info = {}
    domain_info['detail'] = str(data_result)
    return domain_info


def co_za_manage(data_result):
    domain_info = {}
    pattern = re.compile(r'(Registrant:\s\s.*|Email:.*|Tel:.*)')
    match = pattern.findall(data_result)
    print match
    count = len(match)
    for i in range(count):

        if match[i].find('Registrant:') >= 0:
            domain_info['reg_name'] = match[i].split(':')[1].strip()
        elif match[i].find('+') >= 0:
            domain_info['reg_phone'] = match[i].split(':')[1].strip()
        elif match[i].find('@') >= 0:
            domain_info['reg_email'] = match[i].split(':')[1].strip()
    domain_info['detail'] = str(data_result)
    return domain_info


def au_manage(data_result):

    domain_info = {}
    pattern = re.compile(
        r'(Registrant Contact Name:.*|Registrant Contact Email:.*)')
    match = pattern.findall(data_result)
    print match
    count = len(match)

    for i in range(count):

        if match[i].split(':')[0].strip() == 'Registrant Contact Name':
            domain_info['reg_name'] = match[i].split(':')[1].strip()
        elif match[i].split(':')[0].strip() == 'Registrant Contact Email':
            domain_info['reg_email'] = match[i].split(':')[1].strip()
    domain_info['detail'] = str(data_result)
    return domain_info


def am_manage(data_result):

    domain_info = {}
    pattern = re.compile(r'(Administrative contact:\s\s.*|\+.*|.*@.*)')
    match = pattern.findall(data_result)
    print match
    count = len(match)

    for i in range(count):

        if match[i].find('Administrative contact:') >= 0:
            domain_info['reg_name'] = match[i].split(':')[1].strip()
        elif match[i].find('+') >= 0:
            domain_info['reg_phone'] = match[i].strip()
        elif match[i].find('@') >= 0:
            domain_info['reg_email'] = match[i].strip()
    domain_info['detail'] = str(data_result)
    return domain_info


def as_manage(data_result):

    domain_info = {}
    pattern = re.compile(r'(Registrar:\s\s.*)')
    match = pattern.findall(data_result)
    print match
    if match:
        domain_info['reg_name'] = match[0]
    domain_info['detail'] = data_result
    return domain_info


def cn_manage(data_result):
    domain_info = {}
    pattern = re.compile(
        r'(Registrant Phone Number:.*|Registrant:.*|Registrant Contact Email:.*)')
    match = pattern.findall(data_result)
    match_length = len(match)

    print match

    for i in range(match_length):
        if match[i].split(':')[0].strip() == 'Registrant Phone Number':
            domain_info['reg_phone'] = match[i].split(':')[1].strip()
        elif match[i].split(':')[0].strip() == 'Registrant':
            domain_info['reg_name'] = match[i].split(':')[1].strip()
        elif match[i].split(':')[0].strip() == 'Registrant Contact Email':
            domain_info['reg_email'] = match[i].split(':')[1].strip()
    domain_info['detail'] = str(data_result)
    return domain_info


def it_manage(data_result):
    domain_info = {}
    pattern = re.compile(r'(Name:.*)')
    match = pattern.findall(data_result)
    print match
    count = len(match)
    if match:
        domain_info['reg_name'] = match[0].split(':')[1].strip()
    domain_info['detail'] = str(data_result)
    return domain_info


def pl_manage(data_result):
    domain_info = {}
    pattern = re.compile(r'(REGISTRAR:\s\s.*|\+.*|.*@.*)')
    match = pattern.findall(data_result)
    print match
    count = len(match)

    for i in range(count):
        if match[i].find('REGISTRAR:') >= 0:
            domain_info['reg_name'] = match[i].split(':')[1].strip()
        elif match[i].find('+') >= 0:
            domain_info['reg_phone'] = match[i].strip()
        elif match[i].find('@') >= 0:
            domain_info['reg_email'] = match[i].strip()
    domain_info['detail'] = str(data_result)
    return domain_info


def ca_manage(data_result):
    domain_info = {}
    pattern = re.compile(r'Registrar:\n.+Name:(.*)')
    match = pattern.findall(data_result)
    count = len(match)
    if match:
        domain_info['reg_name'] = match[0].strip()
    domain_info['detail'] = str(data_result)
    return domain_info


def ae_manage(data_result):
    domain_info = {}
    pattern = re.compile(
        r'(Registrant Contact Name:.*|Registrant Contact Email:.*)')
    match = pattern.findall(data_result)
    print match
    count = len(match)

    for i in range(count):

        if match[i].split(':')[0].strip() == 'Registrant Contact Name':
            domain_info['reg_name'] = match[i].split(':')[1].strip()
        elif match[i].split(':')[0].strip() == 'Registrant Contact Email':
            domain_info['reg_email'] = match[i].split(':')[1].strip()
    domain_info['detail'] = str(data_result)
    return domain_info


def ro_manage(data_result):
    domain_info = {}
    pattern = re.compile(r'(Domain Name:.*|Registrar:.*)')
    match = pattern.findall(data_result)
    print match
    count = len(match)
    for i in range(count):
        if match[i].split(':')[0].strip() == 'Registrar':
            domain_info['reg_name'] = match[i].split(':')[1].strip()
    domain_info['detail'] = str(data_result)
    return domain_info


def tw_manage(data_result):

    domain_info = {}
    i = 0
    pattern = re.compile(r'(Registrant:\s.*|\+.*)')

    match = pattern.findall(data_result)
    print match
    count = len(match)

    for i in range(count):

        if match[i].split(':')[0].strip() == 'Registrant':

            domain_info['reg_name'] = match[i].split(':')[1].strip()
        elif match[i].find('+') >= 0:
            domain_info['reg_phone'] = match[i].strip()

    pattern_em = re.compile(r'(.*@.*)')
    match_em = pattern_em.findall(data_result)
    print match_em
    if match_em:
        domain_info['reg_email'] = match_em
    domain_info['detail'] = str(data_result)
    return domain_info


def uk_manage(data_result):
    domain_info = {}
    pattern = re.compile(r"(Registrant's address:\s\s.*\s\s.*)")
    match = pattern.findall(data_result)
    match_length = len(match)
    print match

    for i in range(match_length):
        if match[i].split(':')[0].strip() == "Registrant's address":
            domain_info['reg_name'] = match[i].split(
                ':')[1].strip().replace('\r\n      ', ' ')
    domain_info['detail'] = str(data_result)
    return domain_info
