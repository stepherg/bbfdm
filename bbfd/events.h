#ifndef EVENT_H
#define EVENT_H

#include "usp.h"
#include "common.h"

struct event_args_list {
	char *event_arg;
	char *dm_arg;
};

struct event_map_list {
	char *event;
	char *dm_path;
	struct event_args_list args[16];
};

void free_ubus_event_handler(struct ubus_context *ctx, struct list_head *ev_list);
int register_events_to_ubus(struct ubus_context *ctx, struct list_head *ev_list);

#endif /* EVENT_H */
