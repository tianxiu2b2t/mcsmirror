import dns.resolver
import traceback

def get_type_txt(domain: str):
    try:
        answer = get_resolver().query(domain, 'TXT')
        return answer.response.answer[0][0]
    except:
        ...

def get_resolver():
    return dns.resolver.Resolver()

def query_domain(domain: str):
    try:
        answer = get_resolver().query(domain)
        return answer.response.answer[0][0]
    except:
        return None