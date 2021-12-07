/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/nexthop.h>

#include "dns-domain.h"
#include "ip-protocol-list.h"
#include "netif-util.h"
#include "networkd-address.h"
#include "networkd-json.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-neighbor.h"
#include "networkd-nexthop.h"
#include "networkd-network.h"
#include "networkd-route-util.h"
#include "networkd-route.h"
#include "networkd-routing-policy-rule.h"
#include "sort-util.h"
#include "strv.h"
#include "user-util.h"
#include "wifi-util.h"

static int address_build_json(Address *address, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_free_ char *scope = NULL, *flags = NULL, *state = NULL;
        int r;

        assert(address);
        assert(ret);

        r = route_scope_to_string_alloc(address->scope, &scope);
        if (r < 0)
                return r;

        r = address_flags_to_string_alloc(address->flags, address->family, &flags);
        if (r < 0)
                return r;

        r = network_config_state_to_string_alloc(address->state, &state);
        if (r < 0)
                return r;

        r = sd_json_build(&v, SD_JSON_BUILD_OBJECT(
                                SD_JSON_BUILD_PAIR_INTEGER("Family", address->family),
                                SD_JSON_BUILD_PAIR_IN_ADDR("Address", &address->in_addr, address->family),
                                SD_JSON_BUILD_PAIR_IN_ADDR_NON_NULL("Peer", &address->in_addr_peer, address->family),
                                SD_JSON_BUILD_PAIR_IN4_ADDR_NON_NULL("Broadcast", &address->broadcast),
                                SD_JSON_BUILD_PAIR_UNSIGNED("PrefixLength", address->prefixlen),
                                SD_JSON_BUILD_PAIR_UNSIGNED("Scope", address->scope),
                                SD_JSON_BUILD_PAIR_STRING("ScopeString", scope),
                                SD_JSON_BUILD_PAIR_UNSIGNED("Flags", address->flags),
                                SD_JSON_BUILD_PAIR_STRING("FlagsString", flags),
                                SD_JSON_BUILD_PAIR_STRING_NON_EMPTY("Label", address->label),
                                SD_JSON_BUILD_PAIR_FINITE_USEC("PreferredLifetimeUsec", address->lifetime_preferred_usec),
                                SD_JSON_BUILD_PAIR_FINITE_USEC("ValidLifetimeUsec", address->lifetime_valid_usec),
                                SD_JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(address->source)),
                                SD_JSON_BUILD_PAIR_STRING("ConfigState", state),
                                SD_JSON_BUILD_PAIR_IN_ADDR_NON_NULL("ConfigProvider", &address->provider, address->family)));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(v);
        return 0;
}

static int addresses_build_json(Set *addresses, sd_json_variant **ret) {
        sd_json_variant **elements;
        Address *address;
        size_t n = 0;
        int r;

        assert(ret);

        if (set_isempty(addresses)) {
                *ret = NULL;
                return 0;
        }

        elements = new(sd_json_variant*, set_size(addresses));
        if (!elements)
                return -ENOMEM;

        SET_FOREACH(address, addresses) {
                r = address_build_json(address, elements + n);
                if (r < 0)
                        goto finalize;
                n++;
        }

        r = sd_json_build(ret, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("Addresses", SD_JSON_BUILD_VARIANT_ARRAY(elements, n))));

finalize:
        sd_json_variant_unref_many(elements, n);
        free(elements);
        return r;
}

static int neighbor_build_json(Neighbor *n, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_free_ char *state = NULL;
        int r;

        assert(n);
        assert(ret);

        r = network_config_state_to_string_alloc(n->state, &state);
        if (r < 0)
                return r;

        r = sd_json_build(&v, SD_JSON_BUILD_OBJECT(
                                SD_JSON_BUILD_PAIR_INTEGER("Family", n->family),
                                SD_JSON_BUILD_PAIR_IN_ADDR("Destination", &n->in_addr, n->family),
                                SD_JSON_BUILD_PAIR_HW_ADDR("LinkLayerAddress", &n->ll_addr),
                                SD_JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(n->source)),
                                SD_JSON_BUILD_PAIR_STRING("ConfigState", state)));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(v);
        return 0;
}

static int neighbors_build_json(Set *neighbors, sd_json_variant **ret) {
        sd_json_variant **elements;
        Neighbor *neighbor;
        size_t n = 0;
        int r;

        assert(ret);

        if (set_isempty(neighbors)) {
                *ret = NULL;
                return 0;
        }

        elements = new(sd_json_variant*, set_size(neighbors));
        if (!elements)
                return -ENOMEM;

        SET_FOREACH(neighbor, neighbors) {
                r = neighbor_build_json(neighbor, elements + n);
                if (r < 0)
                        goto finalize;
                n++;
        }

        r = sd_json_build(ret, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("Neighbors", SD_JSON_BUILD_VARIANT_ARRAY(elements, n))));

finalize:
        sd_json_variant_unref_many(elements, n);
        free(elements);
        return r;
}

static int nexthop_group_build_json(NextHop *nexthop, sd_json_variant **ret) {
        sd_json_variant **elements;
        struct nexthop_grp *g;
        size_t n = 0;
        int r;

        assert(nexthop);
        assert(ret);

        if (hashmap_isempty(nexthop->group)) {
                *ret = NULL;
                return 0;
        }

        elements = new(sd_json_variant*, hashmap_size(nexthop->group));
        if (!elements)
                return -ENOMEM;

        HASHMAP_FOREACH(g, nexthop->group) {
                r = sd_json_build(elements + n, SD_JSON_BUILD_OBJECT(
                                        SD_JSON_BUILD_PAIR_UNSIGNED("ID", g->id),
                                        SD_JSON_BUILD_PAIR_UNSIGNED("Weight", g->weight+1)));
                if (r < 0)
                        goto failure;

                n++;
        }

        r = sd_json_variant_new_array(ret, elements, n);

failure:
        sd_json_variant_unref_many(elements, n);
        free(elements);
        return r;
}

static int nexthop_build_json(NextHop *n, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL, *group = NULL;
        _cleanup_free_ char *flags = NULL, *protocol = NULL, *state = NULL;
        int r;

        assert(n);
        assert(ret);

        r = route_flags_to_string_alloc(n->flags, &flags);
        if (r < 0)
                return r;

        r = route_protocol_to_string_alloc(n->protocol, &protocol);
        if (r < 0)
                return r;

        r = network_config_state_to_string_alloc(n->state, &state);
        if (r < 0)
                return r;

        r = nexthop_group_build_json(n, &group);
        if (r < 0)
                return r;

        r = sd_json_build(&v, SD_JSON_BUILD_OBJECT(
                                SD_JSON_BUILD_PAIR_UNSIGNED("ID", n->id),
                                SD_JSON_BUILD_PAIR_IN_ADDR_NON_NULL("Gateway", &n->gw, n->family),
                                SD_JSON_BUILD_PAIR_UNSIGNED("Flags", n->flags),
                                SD_JSON_BUILD_PAIR_STRING("FlagsString", strempty(flags)),
                                SD_JSON_BUILD_PAIR_UNSIGNED("Protocol", n->protocol),
                                SD_JSON_BUILD_PAIR_STRING("ProtocolString", protocol),
                                SD_JSON_BUILD_PAIR_BOOLEAN("Blackhole", n->blackhole),
                                SD_JSON_BUILD_PAIR_VARIANT_NON_NULL("Group", group),
                                SD_JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(n->source)),
                                SD_JSON_BUILD_PAIR_STRING("ConfigState", state)));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(v);
        return 0;
}

static int nexthops_build_json(Set *nexthops, sd_json_variant **ret) {
        sd_json_variant **elements;
        NextHop *nexthop;
        size_t n = 0;
        int r;

        assert(ret);

        if (set_isempty(nexthops)) {
                *ret = NULL;
                return 0;
        }

        elements = new(sd_json_variant*, set_size(nexthops));
        if (!elements)
                return -ENOMEM;

        SET_FOREACH(nexthop, nexthops) {
                r = nexthop_build_json(nexthop, elements + n);
                if (r < 0)
                        goto finalize;
                n++;
        }

        r = sd_json_build(ret, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("NextHops", SD_JSON_BUILD_VARIANT_ARRAY(elements, n))));

finalize:
        sd_json_variant_unref_many(elements, n);
        free(elements);
        return r;
}

static int route_build_json(Route *route, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_free_ char *scope = NULL, *protocol = NULL, *table = NULL, *flags = NULL, *state = NULL;
        Manager *manager;
        int r;

        assert(route);
        assert(ret);

        manager = route->link ? route->link->manager : route->manager;

        assert(manager);

        r = route_scope_to_string_alloc(route->scope, &scope);
        if (r < 0)
                return r;

        r = route_protocol_to_string_alloc(route->protocol, &protocol);
        if (r < 0)
                return r;

        r = manager_get_route_table_to_string(manager, route->table, &table);
        if (r < 0)
                return r;

        r = route_flags_to_string_alloc(route->flags, &flags);
        if (r < 0)
                return r;

        r = network_config_state_to_string_alloc(route->state, &state);
        if (r < 0)
                return r;

        r = sd_json_build(&v, SD_JSON_BUILD_OBJECT(
                                SD_JSON_BUILD_PAIR_INTEGER("Family", route->family),
                                SD_JSON_BUILD_PAIR_IN_ADDR("Destination", &route->dst, route->family),
                                SD_JSON_BUILD_PAIR_UNSIGNED("DestinationPrefixLength", route->dst_prefixlen),
                                SD_JSON_BUILD_PAIR_IN_ADDR_NON_NULL("Gateway", &route->gw, route->gw_family),
                                SD_JSON_BUILD_PAIR_IN_ADDR_NON_NULL("Source", &route->src, route->family),
                                SD_JSON_BUILD_PAIR_CONDITION(in_addr_is_set(route->family, &route->src),
                                                          "SourcePrefixLength", SD_JSON_BUILD_UNSIGNED(route->src_prefixlen)),
                                SD_JSON_BUILD_PAIR_IN_ADDR_NON_NULL("PreferredSource", &route->prefsrc, route->family),
                                SD_JSON_BUILD_PAIR_UNSIGNED("Scope", route->scope),
                                SD_JSON_BUILD_PAIR_STRING("ScopeString", scope),
                                SD_JSON_BUILD_PAIR_UNSIGNED("Protocol", route->protocol),
                                SD_JSON_BUILD_PAIR_STRING("ProtocolString", protocol),
                                SD_JSON_BUILD_PAIR_UNSIGNED("Type", route->type),
                                SD_JSON_BUILD_PAIR_STRING("TypeString", route_type_to_string(route->type)),
                                SD_JSON_BUILD_PAIR_UNSIGNED("Priority", route->priority),
                                SD_JSON_BUILD_PAIR_UNSIGNED("Table", route->table),
                                SD_JSON_BUILD_PAIR_STRING("TableString", table),
                                SD_JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("MTU", route->mtu),
                                SD_JSON_BUILD_PAIR_UNSIGNED("Preference", route->pref),
                                SD_JSON_BUILD_PAIR_UNSIGNED("Flags", route->flags),
                                SD_JSON_BUILD_PAIR_STRING("FlagsString", strempty(flags)),
                                SD_JSON_BUILD_PAIR_FINITE_USEC("LifetimeUSec", route->lifetime_usec),
                                SD_JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(route->source)),
                                SD_JSON_BUILD_PAIR_STRING("ConfigState", state),
                                SD_JSON_BUILD_PAIR_IN_ADDR_NON_NULL("ConfigProvider", &route->provider, route->family)));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(v);
        return 0;
}

static int routes_build_json(Set *routes, sd_json_variant **ret) {
        sd_json_variant **elements;
        Route *route;
        size_t n = 0;
        int r;

        assert(ret);

        if (set_isempty(routes)) {
                *ret = NULL;
                return 0;
        }

        elements = new(sd_json_variant*, set_size(routes));
        if (!elements)
                return -ENOMEM;

        SET_FOREACH(route, routes) {
                r = route_build_json(route, elements + n);
                if (r < 0)
                        goto finalize;
                n++;
        }

        r = sd_json_build(ret, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("Routes", SD_JSON_BUILD_VARIANT_ARRAY(elements, n))));

finalize:
        sd_json_variant_unref_many(elements, n);
        free(elements);
        return r;
}

static int routing_policy_rule_build_json(RoutingPolicyRule *rule, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_free_ char *table = NULL, *protocol = NULL, *state = NULL;
        int r;

        assert(rule);
        assert(rule->manager);
        assert(ret);

        r = manager_get_route_table_to_string(rule->manager, rule->table, &table);
        if (r < 0 && r != -EINVAL)
                return r;

        r = route_protocol_to_string_alloc(rule->protocol, &protocol);
        if (r < 0)
                return r;

        r = network_config_state_to_string_alloc(rule->state, &state);
        if (r < 0)
                return r;

        r = sd_json_build(&v, SD_JSON_BUILD_OBJECT(
                                SD_JSON_BUILD_PAIR_INTEGER("Family", rule->family),
                                SD_JSON_BUILD_PAIR_IN_ADDR_NON_NULL("FromPrefix", &rule->from, rule->family),
                                SD_JSON_BUILD_PAIR_CONDITION(in_addr_is_set(rule->family, &rule->from),
                                                          "FromPrefixLength", SD_JSON_BUILD_UNSIGNED(rule->from_prefixlen)),
                                SD_JSON_BUILD_PAIR_IN_ADDR_NON_NULL("ToPrefix", &rule->to, rule->family),
                                SD_JSON_BUILD_PAIR_CONDITION(in_addr_is_set(rule->family, &rule->to),
                                                          "ToPrefixLength", SD_JSON_BUILD_UNSIGNED(rule->to_prefixlen)),
                                SD_JSON_BUILD_PAIR_UNSIGNED("Protocol", rule->protocol),
                                SD_JSON_BUILD_PAIR_STRING("ProtocolString", protocol),
                                SD_JSON_BUILD_PAIR_UNSIGNED("TOS", rule->tos),
                                SD_JSON_BUILD_PAIR_UNSIGNED("Type", rule->type),
                                SD_JSON_BUILD_PAIR_STRING("TypeString", fr_act_type_full_to_string(rule->type)),
                                SD_JSON_BUILD_PAIR_UNSIGNED("IPProtocol", rule->ipproto),
                                SD_JSON_BUILD_PAIR_STRING("IPProtocolString", ip_protocol_to_name(rule->ipproto)),
                                SD_JSON_BUILD_PAIR_UNSIGNED("Priority", rule->priority),
                                SD_JSON_BUILD_PAIR_UNSIGNED("FirewallMark", rule->fwmark),
                                SD_JSON_BUILD_PAIR_UNSIGNED("FirewallMask", rule->fwmask),
                                SD_JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("Table", rule->table),
                                SD_JSON_BUILD_PAIR_STRING_NON_EMPTY("TableString", table),
                                SD_JSON_BUILD_PAIR_BOOLEAN("Invert", rule->invert_rule),
                                SD_JSON_BUILD_PAIR_CONDITION(rule->suppress_prefixlen >= 0,
                                                          "SuppressPrefixLength", SD_JSON_BUILD_UNSIGNED(rule->suppress_prefixlen)),
                                SD_JSON_BUILD_PAIR_CONDITION(rule->suppress_ifgroup >= 0,
                                                          "SuppressInterfaceGroup", SD_JSON_BUILD_UNSIGNED(rule->suppress_ifgroup)),
                                SD_JSON_BUILD_PAIR_CONDITION(rule->sport.start != 0 || rule->sport.end != 0, "SourcePort",
                                                          SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_UNSIGNED(rule->sport.start), SD_JSON_BUILD_UNSIGNED(rule->sport.end))),
                                SD_JSON_BUILD_PAIR_CONDITION(rule->dport.start != 0 || rule->dport.end != 0, "DestinationPort",
                                                          SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_UNSIGNED(rule->dport.start), SD_JSON_BUILD_UNSIGNED(rule->dport.end))),
                                SD_JSON_BUILD_PAIR_CONDITION(rule->uid_range.start != UID_INVALID && rule->uid_range.end != UID_INVALID, "User",
                                                          SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_UNSIGNED(rule->uid_range.start), SD_JSON_BUILD_UNSIGNED(rule->uid_range.end))),
                                SD_JSON_BUILD_PAIR_STRING_NON_EMPTY("IncomingInterface", rule->iif),
                                SD_JSON_BUILD_PAIR_STRING_NON_EMPTY("OutgoingInterface", rule->oif),
                                SD_JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(rule->source)),
                                SD_JSON_BUILD_PAIR_STRING("ConfigState", state)));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(v);
        return 0;
}

static int routing_policy_rules_build_json(Set *rules, sd_json_variant **ret) {
        sd_json_variant **elements;
        RoutingPolicyRule *rule;
        size_t n = 0;
        int r;

        assert(ret);

        if (set_isempty(rules)) {
                *ret = NULL;
                return 0;
        }

        elements = new(sd_json_variant*, set_size(rules));
        if (!elements)
                return -ENOMEM;

        SET_FOREACH(rule, rules) {
                r = routing_policy_rule_build_json(rule, elements + n);
                if (r < 0)
                        goto finalize;
                n++;
        }

        r = sd_json_build(ret, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("RoutingPolicyRules", SD_JSON_BUILD_VARIANT_ARRAY(elements, n))));

finalize:
        sd_json_variant_unref_many(elements, n);
        free(elements);
        return r;
}

static int network_build_json(Network *network, sd_json_variant **ret) {
        assert(ret);

        if (!network) {
                *ret = NULL;
                return 0;
        }

        return sd_json_build(ret, SD_JSON_BUILD_OBJECT(
                                SD_JSON_BUILD_PAIR_STRING("NetworkFile", network->filename),
                                SD_JSON_BUILD_PAIR_BOOLEAN("RequiredForOnline", network->required_for_online),
                                SD_JSON_BUILD_PAIR("RequiredOperationalStateForOnline",
                                                SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_STRING(link_operstate_to_string(network->required_operstate_for_online.min)),
                                                                 SD_JSON_BUILD_STRING(link_operstate_to_string(network->required_operstate_for_online.max)))),
                                SD_JSON_BUILD_PAIR_STRING("RequiredFamilyForOnline",
                                                       link_required_address_family_to_string(network->required_family_for_online)),
                                SD_JSON_BUILD_PAIR_STRING("ActivationPolicy",
                                                       activation_policy_to_string(network->activation_policy))));
}

static int device_build_json(sd_device *device, sd_json_variant **ret) {
        const char *link = NULL, *path = NULL, *vendor = NULL, *model = NULL;

        assert(ret);

        if (!device) {
                *ret = NULL;
                return 0;
        }

        (void) sd_device_get_property_value(device, "ID_NET_LINK_FILE", &link);
        (void) sd_device_get_property_value(device, "ID_PATH", &path);

        if (sd_device_get_property_value(device, "ID_VENDOR_FROM_DATABASE", &vendor) < 0)
                (void) sd_device_get_property_value(device, "ID_VENDOR", &vendor);

        if (sd_device_get_property_value(device, "ID_MODEL_FROM_DATABASE", &model) < 0)
                (void) sd_device_get_property_value(device, "ID_MODEL", &model);

        return sd_json_build(ret, SD_JSON_BUILD_OBJECT(
                                SD_JSON_BUILD_PAIR_STRING_NON_EMPTY("LinkFile", link),
                                SD_JSON_BUILD_PAIR_STRING_NON_EMPTY("Path", path),
                                SD_JSON_BUILD_PAIR_STRING_NON_EMPTY("Vendor", vendor),
                                SD_JSON_BUILD_PAIR_STRING_NON_EMPTY("Model", model)));
}

static int dns_build_json_one(Link *link, const struct in_addr_full *a, NetworkConfigSource s, const union in_addr_union *p, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(link);
        assert(a);
        assert(ret);

        if (a->ifindex != 0 && a->ifindex != link->ifindex) {
                *ret = NULL;
                return 0;
        }

        r = sd_json_build(&v, SD_JSON_BUILD_OBJECT(
                                SD_JSON_BUILD_PAIR_INTEGER("Family", a->family),
                                SD_JSON_BUILD_PAIR_IN_ADDR("Address", &a->address, a->family),
                                SD_JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("Port", a->port),
                                SD_JSON_BUILD_PAIR_CONDITION(a->ifindex != 0, "InterfaceIndex", SD_JSON_BUILD_INTEGER(a->ifindex)),
                                SD_JSON_BUILD_PAIR_STRING_NON_EMPTY("ServerName", a->server_name),
                                SD_JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(s)),
                                SD_JSON_BUILD_PAIR_IN_ADDR_NON_NULL("ConfigProvider", p, a->family)));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(v);
        return 1;
}

static int dns_build_json(Link *link, sd_json_variant **ret) {
        sd_json_variant **elements = NULL;
        size_t n = 0;
        int r;

        assert(link);
        assert(ret);

        if (!link->network) {
                *ret = NULL;
                return 0;
        }

        if (link->n_dns != UINT_MAX) {
                for (unsigned i = 0; i < link->n_dns; i++) {
                        if (!GREEDY_REALLOC(elements, n + 1)) {
                                r = -ENOMEM;
                                goto finalize;
                        }

                        r = dns_build_json_one(link, link->dns[i], NETWORK_CONFIG_SOURCE_RUNTIME, NULL, elements + n);
                        if (r < 0)
                                goto finalize;
                        if (r > 0)
                                n++;
                }
        } else {
                for (unsigned i = 0; i < link->network->n_dns; i++) {
                        if (!GREEDY_REALLOC(elements, n + 1)) {
                                r = -ENOMEM;
                                goto finalize;
                        }

                        r = dns_build_json_one(link, link->network->dns[i], NETWORK_CONFIG_SOURCE_STATIC, NULL, elements + n);
                        if (r < 0)
                                goto finalize;
                        if (r > 0)
                                n++;
                }

                if (link->dhcp_lease && link->network->dhcp_use_dns) {
                        const struct in_addr *dns;
                        union in_addr_union s;
                        int n_dns;

                        r = sd_dhcp_lease_get_server_identifier(link->dhcp_lease, &s.in);
                        if (r < 0)
                                goto finalize;

                        n_dns = sd_dhcp_lease_get_dns(link->dhcp_lease, &dns);
                        for (int i = 0; i < n_dns; i++) {
                                if (!GREEDY_REALLOC(elements, n + 1)) {
                                        r = -ENOMEM;
                                        goto finalize;
                                }

                                r = dns_build_json_one(link,
                                                       &(struct in_addr_full) { .family = AF_INET, .address.in = dns[i], },
                                                       NETWORK_CONFIG_SOURCE_DHCP4,
                                                       &s,
                                                       elements + n);
                                if (r < 0)
                                        goto finalize;
                                if (r > 0)
                                        n++;
                        }
                }

                if (link->dhcp6_lease && link->network->dhcp6_use_dns) {
                        const struct in6_addr *dns;
                        union in_addr_union s;
                        int n_dns;

                        r = sd_dhcp6_lease_get_server_address(link->dhcp6_lease, &s.in6);
                        if (r < 0)
                                goto finalize;

                        n_dns = sd_dhcp6_lease_get_dns(link->dhcp6_lease, &dns);
                        for (int i = 0; i < n_dns; i++) {
                                if (!GREEDY_REALLOC(elements, n + 1)) {
                                        r = -ENOMEM;
                                        goto finalize;
                                }

                                r = dns_build_json_one(link,
                                                       &(struct in_addr_full) { .family = AF_INET6, .address.in6 = dns[i], },
                                                       NETWORK_CONFIG_SOURCE_DHCP6,
                                                       &s,
                                                       elements + n);
                                if (r < 0)
                                        goto finalize;
                                if (r > 0)
                                        n++;
                        }
                }

                if (link->network->ipv6_accept_ra_use_dns) {
                        NDiscRDNSS *a;

                        SET_FOREACH(a, link->ndisc_rdnss) {
                                if (!GREEDY_REALLOC(elements, n + 1)) {
                                        r = -ENOMEM;
                                        goto finalize;
                                }

                                r = dns_build_json_one(link,
                                                       &(struct in_addr_full) { .family = AF_INET6, .address.in6 = a->address, },
                                                       NETWORK_CONFIG_SOURCE_NDISC,
                                                       &(union in_addr_union) { .in6 = a->router },
                                                       elements + n);
                                if (r < 0)
                                        goto finalize;
                                if (r > 0)
                                        n++;
                        }
                }
        }

        if (n == 0) {
                *ret = NULL;
                r = 0;
                goto finalize;
        }

        r = sd_json_build(ret, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("DNS", SD_JSON_BUILD_VARIANT_ARRAY(elements, n))));

finalize:
        sd_json_variant_unref_many(elements, n);
        free(elements);
        return r;
}

static int server_build_json_one_addr(int family, const union in_addr_union *a, NetworkConfigSource s, const union in_addr_union *p, sd_json_variant **ret) {
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(a);
        assert(ret);

        return sd_json_build(ret, SD_JSON_BUILD_OBJECT(
                                SD_JSON_BUILD_PAIR_INTEGER("Family", family),
                                SD_JSON_BUILD_PAIR_IN_ADDR("Address", a, family),
                                SD_JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(s)),
                                SD_JSON_BUILD_PAIR_IN_ADDR_NON_NULL("ConfigProvider", p, family)));
}

static int server_build_json_one_fqdn(int family, const char *fqdn, NetworkConfigSource s, const union in_addr_union *p, sd_json_variant **ret) {
        assert(IN_SET(family, AF_UNSPEC, AF_INET, AF_INET6));
        assert(fqdn);
        assert(ret);

        return sd_json_build(ret, SD_JSON_BUILD_OBJECT(
                                SD_JSON_BUILD_PAIR_STRING("Server", fqdn),
                                SD_JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(s)),
                                SD_JSON_BUILD_PAIR_IN_ADDR_NON_NULL("ConfigProvider", p, family)));
}

static int server_build_json_one_string(const char *str, NetworkConfigSource s, sd_json_variant **ret) {
        union in_addr_union a;
        int family;

        assert(str);
        assert(ret);

        if (in_addr_from_string_auto(str, &family, &a) >= 0)
                return server_build_json_one_addr(family, &a, s, NULL, ret);

        return server_build_json_one_fqdn(AF_UNSPEC, str, s, NULL, ret);
}

static int ntp_build_json(Link *link, sd_json_variant **ret) {
        sd_json_variant **elements = NULL;
        size_t n = 0;
        char **p;
        int r;

        assert(link);
        assert(ret);

        if (!link->network) {
                *ret = NULL;
                return 0;
        }

        STRV_FOREACH(p, link->ntp ?: link->network->ntp) {
                if (!GREEDY_REALLOC(elements, n + 1)) {
                        r = -ENOMEM;
                        goto finalize;
                }

                r = server_build_json_one_string(*p, NETWORK_CONFIG_SOURCE_RUNTIME, elements + n);
                if (r < 0)
                        goto finalize;

                n++;
        }

        if (!link->ntp) {
                if (link->dhcp_lease && link->network->dhcp_use_ntp) {
                        const struct in_addr *ntp;
                        union in_addr_union s;
                        int n_ntp;

                        r = sd_dhcp_lease_get_server_identifier(link->dhcp_lease, &s.in);
                        if (r < 0)
                                goto finalize;

                        n_ntp = sd_dhcp_lease_get_ntp(link->dhcp_lease, &ntp);
                        for (int i = 0; i < n_ntp; i++) {
                                if (!GREEDY_REALLOC(elements, n + 1)) {
                                        r = -ENOMEM;
                                        goto finalize;
                                }

                                r = server_build_json_one_addr(AF_INET,
                                                               &(union in_addr_union) { .in = ntp[i], },
                                                               NETWORK_CONFIG_SOURCE_DHCP4,
                                                               &s,
                                                               elements + n);
                                if (r < 0)
                                        goto finalize;

                                n++;
                        }
                }

                if (link->dhcp6_lease && link->network->dhcp6_use_ntp) {
                        const struct in6_addr *ntp_addr;
                        union in_addr_union s;
                        char **ntp_fqdn;
                        int n_ntp;

                        r = sd_dhcp6_lease_get_server_address(link->dhcp6_lease, &s.in6);
                        if (r < 0)
                                goto finalize;

                        n_ntp = sd_dhcp6_lease_get_ntp_addrs(link->dhcp6_lease, &ntp_addr);
                        for (int i = 0; i < n_ntp; i++) {
                                if (!GREEDY_REALLOC(elements, n + 1)) {
                                        r = -ENOMEM;
                                        goto finalize;
                                }

                                r = server_build_json_one_addr(AF_INET6,
                                                               &(union in_addr_union) { .in6 = ntp_addr[i], },
                                                               NETWORK_CONFIG_SOURCE_DHCP6,
                                                               &s,
                                                               elements + n);
                                if (r < 0)
                                        goto finalize;

                                n++;
                        }

                        n_ntp = sd_dhcp6_lease_get_ntp_fqdn(link->dhcp6_lease, &ntp_fqdn);
                        for (int i = 0; i < n_ntp; i++) {
                                if (!GREEDY_REALLOC(elements, n + 1)) {
                                        r = -ENOMEM;
                                        goto finalize;
                                }

                                r = server_build_json_one_fqdn(AF_INET6,
                                                               ntp_fqdn[i],
                                                               NETWORK_CONFIG_SOURCE_DHCP6,
                                                               &s,
                                                               elements + n);
                                if (r < 0)
                                        goto finalize;

                                n++;
                        }
                }
        }

        if (n == 0) {
                *ret = NULL;
                return 0;
        }

        r = sd_json_build(ret, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("NTP", SD_JSON_BUILD_VARIANT_ARRAY(elements, n))));

finalize:
        sd_json_variant_unref_many(elements, n);
        free(elements);
        return r;
}

static int sip_build_json(Link *link, sd_json_variant **ret) {
        const struct in_addr *sip;
        sd_json_variant **elements;
        union in_addr_union s;
        size_t n = 0;
        int n_sip, r;

        assert(link);
        assert(ret);

        if (!link->network || !link->network->dhcp_use_sip || !link->dhcp_lease) {
                *ret = NULL;
                return 0;
        }

        n_sip = sd_dhcp_lease_get_sip(link->dhcp_lease, &sip);
        if (n_sip <= 0) {
                *ret = NULL;
                return 0;
        }

        r = sd_dhcp_lease_get_server_identifier(link->dhcp_lease, &s.in);
        if (r < 0)
                return r;

        elements = new(sd_json_variant*, n_sip);
        if (!elements)
                return -ENOMEM;

        for (int i = 0; i < n_sip; i++) {
                r = server_build_json_one_addr(AF_INET,
                                               &(union in_addr_union) { .in = sip[i], },
                                               NETWORK_CONFIG_SOURCE_DHCP4,
                                               &s,
                                               elements + n);
                if (r < 0)
                        goto finalize;
                if (r > 0)
                        n++;
        }

        r = sd_json_build(ret, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("SIP", SD_JSON_BUILD_VARIANT_ARRAY(elements, n))));

finalize:
        sd_json_variant_unref_many(elements, n);
        free(elements);
        return r;
}

static int domain_build_json(int family, const char *domain, NetworkConfigSource s, const union in_addr_union *p, sd_json_variant **ret) {
        assert(IN_SET(family, AF_UNSPEC, AF_INET, AF_INET6));
        assert(domain);
        assert(ret);

        return sd_json_build(ret, SD_JSON_BUILD_OBJECT(
                                SD_JSON_BUILD_PAIR_STRING("Domain", domain),
                                SD_JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(s)),
                                SD_JSON_BUILD_PAIR_IN_ADDR_NON_NULL("ConfigProvider", p, family)));
}

static int domains_build_json(Link *link, bool is_route, sd_json_variant **ret) {
        OrderedSet *link_domains, *network_domains;
        sd_json_variant **elements = NULL;
        DHCPUseDomains use_domains;
        union in_addr_union s;
        char **p, **domains;
        const char *domain;
        size_t n = 0;
        int r;

        assert(link);
        assert(ret);

        if (!link->network) {
                *ret = NULL;
                return 0;
        }

        link_domains = is_route ? link->route_domains : link->search_domains;
        network_domains = is_route ? link->network->route_domains : link->network->search_domains;
        use_domains = is_route ? DHCP_USE_DOMAINS_ROUTE : DHCP_USE_DOMAINS_YES;

        ORDERED_SET_FOREACH(domain, link_domains ?: network_domains) {
                if (!GREEDY_REALLOC(elements, n + 1)) {
                        r = -ENOMEM;
                        goto finalize;
                }

                r = domain_build_json(AF_UNSPEC, domain,
                                      link_domains ? NETWORK_CONFIG_SOURCE_RUNTIME : NETWORK_CONFIG_SOURCE_STATIC,
                                      NULL, elements + n);
                if (r < 0)
                        goto finalize;

                n++;
        }

        if (!link_domains) {
                if (link->dhcp_lease &&
                    link->network->dhcp_use_domains == use_domains) {
                        r = sd_dhcp_lease_get_server_identifier(link->dhcp_lease, &s.in);
                        if (r < 0)
                                goto finalize;

                        if (sd_dhcp_lease_get_domainname(link->dhcp_lease, &domain) >= 0) {
                                if (!GREEDY_REALLOC(elements, n + 1)) {
                                        r = -ENOMEM;
                                        goto finalize;
                                }

                                r = domain_build_json(AF_INET, domain, NETWORK_CONFIG_SOURCE_DHCP4, &s, elements + n);
                                if (r < 0)
                                        goto finalize;

                                n++;
                        }

                        if (sd_dhcp_lease_get_search_domains(link->dhcp_lease, &domains) >= 0) {
                                STRV_FOREACH(p, domains) {
                                        if (!GREEDY_REALLOC(elements, n + 1)) {
                                                r = -ENOMEM;
                                                goto finalize;
                                        }

                                        r = domain_build_json(AF_INET, *p, NETWORK_CONFIG_SOURCE_DHCP4, &s, elements + n);
                                        if (r < 0)
                                                goto finalize;

                                        n++;
                                }
                        }
                }

                if (link->dhcp6_lease &&
                    link->network->dhcp6_use_domains == use_domains) {
                        r = sd_dhcp6_lease_get_server_address(link->dhcp6_lease, &s.in6);
                        if (r < 0)
                                goto finalize;

                        if (sd_dhcp6_lease_get_domains(link->dhcp6_lease, &domains) >= 0) {
                                STRV_FOREACH(p, domains) {
                                        if (!GREEDY_REALLOC(elements, n + 1)) {
                                                r = -ENOMEM;
                                                goto finalize;
                                        }

                                        r = domain_build_json(AF_INET6, *p, NETWORK_CONFIG_SOURCE_DHCP6, &s, elements + n);
                                        if (r < 0)
                                                goto finalize;

                                        n++;
                                }
                        }
                }

                if (link->network->ipv6_accept_ra_use_domains == use_domains) {
                        NDiscDNSSL *a;

                        SET_FOREACH(a, link->ndisc_dnssl) {
                                if (!GREEDY_REALLOC(elements, n + 1)) {
                                        r = -ENOMEM;
                                        goto finalize;
                                }

                                r = domain_build_json(AF_INET6, NDISC_DNSSL_DOMAIN(a), NETWORK_CONFIG_SOURCE_NDISC,
                                                      &(union in_addr_union) { .in6 = a->router },
                                                      elements + n);
                                if (r < 0)
                                        goto finalize;

                                n++;
                        }
                }
        }

        if (n == 0) {
                *ret = NULL;
                return 0;
        }

        r = sd_json_build(ret, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR(is_route ? "RouteDomains" : "SearchDomains",
                                                              SD_JSON_BUILD_VARIANT_ARRAY(elements, n))));

finalize:
        sd_json_variant_unref_many(elements, n);
        free(elements);
        return r;
}

static int nta_build_json(const char *nta, NetworkConfigSource s, sd_json_variant **ret) {
        assert(nta);
        assert(ret);

        return sd_json_build(ret, SD_JSON_BUILD_OBJECT(
                                SD_JSON_BUILD_PAIR_STRING("DNSSECNegativeTrustAnchor", nta),
                                SD_JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(s))));
}

static int ntas_build_json(Link *link, sd_json_variant **ret) {
        sd_json_variant **elements = NULL;
        const char *nta;
        size_t n = 0;
        int r;

        assert(link);
        assert(ret);

        if (!link->network) {
                *ret = NULL;
                return 0;
        }

        SET_FOREACH(nta, link->dnssec_negative_trust_anchors ?: link->network->dnssec_negative_trust_anchors) {
                if (!GREEDY_REALLOC(elements, n + 1)) {
                        r = -ENOMEM;
                        goto finalize;
                }

                r = nta_build_json(nta,
                                   link->dnssec_negative_trust_anchors ? NETWORK_CONFIG_SOURCE_RUNTIME : NETWORK_CONFIG_SOURCE_STATIC,
                                   elements + n);
                if (r < 0)
                        goto finalize;

                n++;
        }

        if (n == 0) {
                *ret = NULL;
                return 0;
        }

        r = sd_json_build(ret, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("DNSSECNegativeTrustAnchors",
                                                              SD_JSON_BUILD_VARIANT_ARRAY(elements, n))));

finalize:
        sd_json_variant_unref_many(elements, n);
        free(elements);
        return r;
}

static int dns_misc_build_json(Link *link, sd_json_variant **ret) {
        sd_json_variant **elements = NULL;
        ResolveSupport resolve_support;
        NetworkConfigSource source;
        DnsOverTlsMode mode;
        size_t n = 0;
        int t, r;

        assert(link);
        assert(ret);

        if (!link->network) {
                *ret = NULL;
                return 0;
        }

        resolve_support = link->llmnr >= 0 ? link->llmnr : link->network->llmnr;
        if (resolve_support >= 0) {
                source = link->llmnr >= 0 ? NETWORK_CONFIG_SOURCE_RUNTIME : NETWORK_CONFIG_SOURCE_STATIC;

                if (!GREEDY_REALLOC(elements, n + 1)) {
                        r = -ENOMEM;
                        goto finalize;
                }

                r = sd_json_build(elements + n, SD_JSON_BUILD_OBJECT(
                                        SD_JSON_BUILD_PAIR_STRING("LLMNR", resolve_support_to_string(resolve_support)),
                                        SD_JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(source))));
                if (r < 0)
                        goto finalize;

                n++;
        }

        resolve_support = link->mdns >= 0 ? link->mdns : link->network->mdns;
        if (resolve_support >= 0) {
                source = link->mdns >= 0 ? NETWORK_CONFIG_SOURCE_RUNTIME : NETWORK_CONFIG_SOURCE_STATIC;

                if (!GREEDY_REALLOC(elements, n + 1)) {
                        r = -ENOMEM;
                        goto finalize;
                }

                r = sd_json_build(elements + n, SD_JSON_BUILD_OBJECT(
                                        SD_JSON_BUILD_PAIR_STRING("MDNS", resolve_support_to_string(resolve_support)),
                                        SD_JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(source))));
                if (r < 0)
                        goto finalize;

                n++;
        }

        t = link->dns_default_route >= 0 ? link->dns_default_route : link->network->dns_default_route;
        if (t >= 0) {
                source = link->dns_default_route >= 0 ? NETWORK_CONFIG_SOURCE_RUNTIME : NETWORK_CONFIG_SOURCE_STATIC;

                if (!GREEDY_REALLOC(elements, n + 1)) {
                        r = -ENOMEM;
                        goto finalize;
                }

                r = sd_json_build(elements + n, SD_JSON_BUILD_OBJECT(
                                        SD_JSON_BUILD_PAIR_BOOLEAN("DNSDefaultRoute", t),
                                        SD_JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(source))));
                if (r < 0)
                        goto finalize;

                n++;
        }

        mode = link->dns_over_tls_mode >= 0 ? link->dns_over_tls_mode : link->network->dns_over_tls_mode;
        if (mode >= 0) {
                source = link->dns_over_tls_mode >= 0 ? NETWORK_CONFIG_SOURCE_RUNTIME : NETWORK_CONFIG_SOURCE_STATIC;

                if (!GREEDY_REALLOC(elements, n + 1)) {
                        r = -ENOMEM;
                        goto finalize;
                }

                r = sd_json_build(elements + n, SD_JSON_BUILD_OBJECT(
                                        SD_JSON_BUILD_PAIR_STRING("DNSOverTLS", dns_over_tls_mode_to_string(mode)),
                                        SD_JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(source))));
                if (r < 0)
                        goto finalize;

                n++;
        }

        r = sd_json_build(ret, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("DNSSettings",
                                                              SD_JSON_BUILD_VARIANT_ARRAY(elements, n))));

finalize:
        sd_json_variant_unref_many(elements, n);
        free(elements);
        return r;
}

int link_build_json(Link *link, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL, *w = NULL;
        _cleanup_free_ char *type = NULL, *flags = NULL;
        int r;

        assert(link);
        assert(ret);

        r = net_get_type_string(link->sd_device, link->iftype, &type);
        if (r == -ENOMEM)
                return r;

        r = link_flags_to_string_alloc(link->flags, &flags);
        if (r < 0)
                return r;

        r = sd_json_build(&v, SD_JSON_BUILD_OBJECT(
                                /* basic information */
                                SD_JSON_BUILD_PAIR_INTEGER("Index", link->ifindex),
                                SD_JSON_BUILD_PAIR_STRING("Name", link->ifname),
                                SD_JSON_BUILD_PAIR_STRV_NON_EMPTY("AlternativeNames", link->alternative_names),
                                SD_JSON_BUILD_PAIR_CONDITION(link->master_ifindex > 0,
                                                          "MasterInterfaceIndex", SD_JSON_BUILD_INTEGER(link->master_ifindex)),
                                SD_JSON_BUILD_PAIR_STRING_NON_EMPTY("Kind", link->kind),
                                SD_JSON_BUILD_PAIR_STRING("Type", type),
                                SD_JSON_BUILD_PAIR_STRING_NON_EMPTY("Driver", link->driver),
                                SD_JSON_BUILD_PAIR_UNSIGNED("Flags", link->flags),
                                SD_JSON_BUILD_PAIR_STRING("FlagsString", flags),
                                SD_JSON_BUILD_PAIR_UNSIGNED("KernelOperationalState", link->kernel_operstate),
                                SD_JSON_BUILD_PAIR_STRING("KernelOperationalStateString", kernel_operstate_to_string(link->kernel_operstate)),
                                SD_JSON_BUILD_PAIR_UNSIGNED("MTU", link->mtu),
                                SD_JSON_BUILD_PAIR_UNSIGNED("MinimumMTU", link->min_mtu),
                                SD_JSON_BUILD_PAIR_UNSIGNED("MaximumMTU", link->max_mtu),
                                SD_JSON_BUILD_PAIR_HW_ADDR_NON_NULL("HardwareAddress", &link->hw_addr),
                                SD_JSON_BUILD_PAIR_HW_ADDR_NON_NULL("PermanentHardwareAddress", &link->permanent_hw_addr),
                                SD_JSON_BUILD_PAIR_HW_ADDR_NON_NULL("BroadcastAddress", &link->bcast_addr),
                                SD_JSON_BUILD_PAIR_IN6_ADDR_NON_NULL("IPv6LinkLocalAddress", &link->ipv6ll_address),
                                /* wlan information */
                                SD_JSON_BUILD_PAIR_CONDITION(link->wlan_iftype > 0, "WirelessLanInterfaceType",
                                                          SD_JSON_BUILD_UNSIGNED(link->wlan_iftype)),
                                SD_JSON_BUILD_PAIR_CONDITION(link->wlan_iftype > 0, "WirelessLanInterfaceTypeString",
                                                          SD_JSON_BUILD_STRING(nl80211_iftype_to_string(link->wlan_iftype))),
                                SD_JSON_BUILD_PAIR_STRING_NON_EMPTY("SSID", link->ssid),
                                SD_JSON_BUILD_PAIR_ETHER_ADDR_NON_NULL("BSSID", &link->bssid),
                                /* link state */
                                SD_JSON_BUILD_PAIR_STRING("SetupState", link_state_to_string(link->state)),
                                SD_JSON_BUILD_PAIR_STRING("OperationalState", link_operstate_to_string(link->operstate)),
                                SD_JSON_BUILD_PAIR_STRING("CarrierState", link_carrier_state_to_string(link->carrier_state)),
                                SD_JSON_BUILD_PAIR_STRING("AddressState", link_address_state_to_string(link->address_state)),
                                SD_JSON_BUILD_PAIR_STRING("IPv4AddressState", link_address_state_to_string(link->ipv4_address_state)),
                                SD_JSON_BUILD_PAIR_STRING("IPv6AddressState", link_address_state_to_string(link->ipv6_address_state)),
                                SD_JSON_BUILD_PAIR_STRING("OnlineState", link_online_state_to_string(link->online_state))));
        if (r < 0)
                return r;

        r = network_build_json(link->network, &w);
        if (r < 0)
                return r;

        r = sd_json_variant_merge(&v, w);
        if (r < 0)
                return r;

        w = sd_json_variant_unref(w);

        r = device_build_json(link->sd_device, &w);
        if (r < 0)
                return r;

        r = sd_json_variant_merge(&v, w);
        if (r < 0)
                return r;

        w = sd_json_variant_unref(w);

        r = dns_build_json(link, &w);
        if (r < 0)
                return r;

        r = sd_json_variant_merge(&v, w);
        if (r < 0)
                return r;

        w = sd_json_variant_unref(w);

        r = ntp_build_json(link, &w);
        if (r < 0)
                return r;

        r = sd_json_variant_merge(&v, w);
        if (r < 0)
                return r;

        w = sd_json_variant_unref(w);

        r = sip_build_json(link, &w);
        if (r < 0)
                return r;

        r = sd_json_variant_merge(&v, w);
        if (r < 0)
                return r;

        w = sd_json_variant_unref(w);

        r = domains_build_json(link, /* is_route = */ false, &w);
        if (r < 0)
                return r;

        r = sd_json_variant_merge(&v, w);
        if (r < 0)
                return r;

        w = sd_json_variant_unref(w);

        r = domains_build_json(link, /* is_route = */ true, &w);
        if (r < 0)
                return r;

        r = sd_json_variant_merge(&v, w);
        if (r < 0)
                return r;

        w = sd_json_variant_unref(w);

        r = ntas_build_json(link, &w);
        if (r < 0)
                return r;

        r = sd_json_variant_merge(&v, w);
        if (r < 0)
                return r;

        w = sd_json_variant_unref(w);

        r = dns_misc_build_json(link, &w);
        if (r < 0)
                return r;

        r = sd_json_variant_merge(&v, w);
        if (r < 0)
                return r;

        w = sd_json_variant_unref(w);

        r = addresses_build_json(link->addresses, &w);
        if (r < 0)
                return r;

        r = sd_json_variant_merge(&v, w);
        if (r < 0)
                return r;

        w = sd_json_variant_unref(w);

        r = neighbors_build_json(link->neighbors, &w);
        if (r < 0)
                return r;

        r = sd_json_variant_merge(&v, w);
        if (r < 0)
                return r;

        w = sd_json_variant_unref(w);

        r = nexthops_build_json(link->nexthops, &w);
        if (r < 0)
                return r;

        r = sd_json_variant_merge(&v, w);
        if (r < 0)
                return r;

        w = sd_json_variant_unref(w);

        r = routes_build_json(link->routes, &w);
        if (r < 0)
                return r;

        r = sd_json_variant_merge(&v, w);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(v);
        return 0;
}

static int link_json_compare(sd_json_variant * const *a, sd_json_variant * const *b) {
        int64_t index_a, index_b;

        assert(a && *a);
        assert(b && *b);

        index_a = sd_json_variant_integer(sd_json_variant_by_key(*a, "Index"));
        index_b = sd_json_variant_integer(sd_json_variant_by_key(*b, "Index"));

        return CMP(index_a, index_b);
}

static int links_build_json(Manager *manager, sd_json_variant **ret) {
        sd_json_variant **elements;
        Link *link;
        size_t n = 0;
        int r;

        assert(manager);
        assert(ret);

        elements = new(sd_json_variant*, hashmap_size(manager->links_by_index));
        if (!elements)
                return -ENOMEM;

        HASHMAP_FOREACH(link, manager->links_by_index) {
                r = link_build_json(link, elements + n);
                if (r < 0)
                        goto finalize;
                n++;
        }

        typesafe_qsort(elements, n, link_json_compare);

        r = sd_json_build(ret, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("Interfaces", SD_JSON_BUILD_VARIANT_ARRAY(elements, n))));

finalize:
        sd_json_variant_unref_many(elements, n);
        free(elements);
        return r;
}

int manager_build_json(Manager *manager, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL, *w = NULL;
        int r;

        assert(manager);
        assert(ret);

        r = links_build_json(manager, &v);
        if (r < 0)
                return r;

        r = nexthops_build_json(manager->nexthops, &w);
        if (r < 0)
                return r;

        r = sd_json_variant_merge(&v, w);
        if (r < 0)
                return r;

        w = sd_json_variant_unref(w);

        r = routes_build_json(manager->routes, &w);
        if (r < 0)
                return r;

        r = sd_json_variant_merge(&v, w);
        if (r < 0)
                return r;

        w = sd_json_variant_unref(w);

        r = routing_policy_rules_build_json(manager->rules, &w);
        if (r < 0)
                return r;

        r = sd_json_variant_merge(&v, w);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(v);
        return 0;
}
