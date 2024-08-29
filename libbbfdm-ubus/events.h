#ifndef EVENT_H
#define EVENT_H

int register_events_to_ubus(struct ubus_context *ctx, struct list_head *ev_list);
void free_ubus_event_handler(struct ubus_context *ctx, struct list_head *ev_list);

#endif /* EVENT_H */
