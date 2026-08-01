#ifndef COMRADE_NAT_H
#define COMRADE_NAT_H

struct nat_agent;

struct nat_agent *nat_agent_create(void);
void nat_agent_free(struct nat_agent *agent);

#endif
