
import os
from collections import defaultdict

from twisted.internet import defer
from twisted.names import dns, common, error
from twisted.python import failure

class DnsforeverAuthority(common.ResolverBase):
    """
    An Authority that is loaded from a master server.

    @ivar _ADDITIONAL_PROCESSING_TYPES: Record types for which additional
        processing will be done.
    @ivar _ADDRESS_TYPES: Record types which are useful for inclusion in the
        additional section generated during additional processing.
    """
    # See https://twistedmatrix.com/trac/ticket/6650
    _ADDITIONAL_PROCESSING_TYPES = (dns.CNAME, dns.MX, dns.NS)
    _ADDRESS_TYPES = (dns.A, dns.AAAA)

    zones = None

    def __init__(self, serverAddr):
        common.ResolverBase.__init__(self)
        self.serverAddr = serverAddr
        self.zones = defaultdict(lambda: None)

    def update(self):
        self.records = {}
        self.addRecord('dnsforever.kr', 300, 'A', 'www', 'IN', ['1.2.3.4'])
        #self.addRecord('test.dnsforever.kr', 300, dns.A, 'www', 'IN', ['1.2.3.4'])

    def _additionalRecords(self, answer, authority):
        """
        Find locally known information that could be useful to the consumer of
        the response and construct appropriate records to include in the
        I{additional} section of that response.

        Essentially, implement RFC 1034 section 4.3.2 step 6.

        @param answer: A L{list} of the records which will be included in the
            I{answer} section of the response.

        @param authority: A L{list} of the records which will be included in
            the I{authority} section of the response.

        @return: A generator of L{dns.RRHeader} instances for inclusion in the
            I{additional} section.  These instances represent extra information
            about the records in C{answer} and C{authority}.
        """
        for record in answer + authority:
            if record.type in self._ADDITIONAL_PROCESSING_TYPES:
                name = record.payload.name.name
                for rec in self.records.get(name.lower(), ()):
                    if rec.TYPE in self._ADDRESS_TYPES:
                        yield dns.RRHeader(
                            name, rec.TYPE, dns.IN,
                            rec.ttl, rec, auth=True)

    def _lookup(self, name, cls, type, timeout = None):
        """
        Determine a response to a particular DNS query.

        @param name: The name which is being queried and for which to lookup a
            response.
        @type name: L{bytes}

        @param cls: The class which is being queried.  Only I{IN} is
            implemented here and this value is presently disregarded.
        @type cls: L{int}

        @param type: The type of records being queried.  See the types defined
            in L{twisted.names.dns}.
        @type type: L{int}

        @param timeout: All processing is done locally and a result is
            available immediately, so the timeout value is ignored.

        @return: A L{Deferred} that fires with a L{tuple} of three sets of
            response records (to comprise the I{answer}, I{authority}, and
            I{additional} sections of a DNS response) or with a L{Failure} if
            there is a problem processing the query.
        """
        cnames = []
        results = []
        authority = []
        additional = []

        zone_name = name.lower()
        while zone_name:
            if self.zones[zone_name]:
                domain_zone = self.zones[zone_name]
                break

            if zone_name.find('.') != -1:
                zone_name = zone_name.split('.', 1)[1]
            else:
                return defer.fail(failure.Failure(error.DomainError(name)))

        domain_records = domain_zone.get(name.lower())
        if not domain_records:
            return defer.fail(failure.Failure(dns.AuthoritativeDomainError(name)))

        for record in domain_records:
            ttl = record.ttl

            if record.TYPE == dns.NS and name.lower() != self.soa[0].lower():
                # NS record belong to a child zone: this is a referral.  As
                # NS records are authoritative in the child zone, ours here
                # are not.  RFC 2181, section 6.1.
                authority.append(
                    dns.RRHeader(name, record.TYPE, dns.IN, ttl, record, auth=False)
                )
            elif record.TYPE == type or type == dns.ALL_RECORDS:
                results.append(
                    dns.RRHeader(name, record.TYPE, dns.IN, ttl, record, auth=True)
                )
            if record.TYPE == dns.CNAME:
                cnames.append(
                    dns.RRHeader(name, record.TYPE, dns.IN, ttl, record, auth=True)
                )
        if not results:
            results = cnames

        # https://tools.ietf.org/html/rfc1034#section-4.3.2 - sort of.
        # See https://twistedmatrix.com/trac/ticket/6732
        additionalInformation = self._additionalRecords(results, authority)
        if cnames:
            results.extend(additionalInformation)
        else:
            additional.extend(additionalInformation)

        if not results and not authority:
            # Empty response. Include SOA record to allow clients to cache
            # this response.  RFC 1034, sections 3.7 and 4.3.4, and RFC 2181
            # section 7.1.
            authority.append(
                dns.RRHeader(self.soa[0], dns.SOA, dns.IN, ttl, self.soa[1], auth=True)
                )
        return defer.succeed((results, authority, additional))

    def delZone(self, zone_name):
        if self.zones[zone_name]:
            del self.zones[zone_name]

    def addRecord(self, zone_name, ttl, type, subdomain, cls, rdata):
        if not self.zones[zone_name]:
            self.zones[zone_name] = {}

        domain = subdomain + '.' + zone_name

        record = getattr(dns, 'Record_%s' % type, None)
        if not record:
            raise NotImplementedError, "Record type %r not supported" % type

        r = record(*rdata)
        r.ttl = ttl

        self.zones[zone_name].setdefault(domain.lower(), []).append(r)

        print 'Adding IN Record', domain, ttl, r
        # if type == 'SOA':
        #     self.soa = (domain, r)