#include <stdio.h>

#include <libbbf_ubus/libbbf_ubus.h>
#include <libbbf_api/dmbbf.h>
#include <libubox/uloop.h>

extern DM_MAP_OBJ tDynamicObj[];

int main(int argc, char *argv[])
{
	struct ubus_context *ctx = ubus_connect(NULL);

	if (!ctx) {
		printf("Failed to connect to ubus\n\r");
		return -1;
	}

	printf("Sending entry obj: (%s)\n\r", tDynamicObj[0].path);

	ubus_add_uloop(ctx);

	if (-1 == dynamicdm_init_plugin_object(ctx, "dmtest", tDynamicObj)) {
		printf("Failed to create ubus object\n\r");
		return -1;
	}

	uloop_run();

	dynamicdm_free_plugin_object(ctx, "dmtest");
	ubus_free(ctx);
	uloop_done();

	return 0;
}
