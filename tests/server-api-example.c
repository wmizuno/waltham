/*
 * Copyright © 2016 DENSO CORPORATION
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <assert.h>
#include <signal.h>

#include <waltham-object.h>
#include <waltham-server.h>
#include <waltham-connection.h>

#include "w-util.h"

#define MAX_EPOLL_WATCHES 2

struct server;
struct client;

/* epoll structure */
struct watch {
	struct server *server;
	int fd;
	void (*cb)(struct watch *w, uint32_t events);
};

/* wthp_region protocol object */
struct region {
	struct wthp_region *obj;
	/* pixman_region32_t region; */
	struct wl_list link; /* struct client::region_list */
};

/* wthp_compositor protocol object */
struct compositor {
	struct wthp_compositor *obj;
	struct client *client;
	struct wl_list link; /* struct client::compositor_list */
};

/* wthp_blob_factory protocol object */
struct blob_factory {
	struct wthp_blob_factory *obj;
	struct client *client;
	struct wl_list link; /* struct client::blob_factory_list */
};

/* wthp_buffer protocol object */
struct buffer {
	struct wthp_buffer *obj;
	uint32_t data_sz;
	void *data;
	int32_t width;
	int32_t height;
	int32_t stride;
	uint32_t format;
	struct wl_list link; /* struct client::blob_factory_list */
};

/* wthp_surface protocol object */
struct surface {
	struct wthp_surface *obj;
	uint32_t ivi_id;
	struct wthp_callback *cb;
	struct wl_list link; /* struct client::surface_list */
};

/* wthp_ivi_surface protocol object */
struct ivisurface {
	struct wthp_ivi_surface *obj;
	struct surface *surf;
};

/* wthp_ivi_application protocol object */
struct application {
	struct wthp_ivi_application *obj;
	struct client *client;
	struct wl_list link; /* struct client::surface_list */
};

/* wthp_registry protocol object */
struct registry {
	struct wthp_registry *obj;
	struct client *client;
	struct wl_list link; /* struct client::registry_list */
};

struct client {
	struct wl_list link; /* struct server::client_list */
	struct server *server;

	struct wth_connection *connection;
	struct watch conn_watch;

	/* client object lists for clean-up on disconnection */
	struct wl_list registry_list;     /* struct registry::link */
	struct wl_list compositor_list;   /* struct compositor::link */
	struct wl_list region_list;       /* struct region::link */
	struct wl_list surface_list;      /* struct surface::link */
	struct wl_list blob_factory_list; /* struct blob_factory::link */
	struct wl_list buffer_list; /* struct blob_factory::link */
};

struct server {
	int listen_fd;
	struct watch listen_watch;

	bool running;
	int epoll_fd;

	struct wl_list client_list; /* struct client::link */
};

static int
watch_ctl(struct watch *w, int op, uint32_t events)
{
	struct epoll_event ee;

	ee.events = events;
	ee.data.ptr = w;
	return epoll_ctl(w->server->epoll_fd, op, w->fd, &ee);
}

static void
client_post_out_of_memory(struct client *c)
{
	struct wth_display *disp;

	disp = wth_connection_get_display(c->connection);
	wth_object_post_error((struct wth_object *)disp, 1,
			      "out of memory");
}

/* BEGIN wthp_surface implementation */

static void
surface_destroy(struct surface *surface)
{
        fprintf(stderr, "surface %p destroy\n", surface->obj);

        wthp_surface_free(surface->obj);
        wl_list_remove(&surface->link);
        free(surface);
}

static void
surface_handle_destroy(struct wthp_surface *wthp_surface)
{
	struct surface *surface = wth_object_get_user_data((struct wth_object *)wthp_surface);

	assert(wthp_surface == surface->obj);

	surface_destroy(surface);
}

static void
surface_handle_attach(struct wthp_surface *wthp_surface,
		      struct wthp_buffer *buffer, int32_t x, int32_t y)
{
        fprintf(stderr, "surface %p attach(%p, %d, %d)\n",
                wthp_surface, buffer, x, y);

	wthp_buffer_send_complete(buffer, 0);
}

static void
surface_handle_damage(struct wthp_surface *wthp_surface,
		      int32_t x, int32_t y, int32_t width, int32_t height)
{
        fprintf(stderr, "surface %p damage(%d, %d, %d, %d)\n",
                wthp_surface, x, y, width, height);
}

static void
surface_handle_frame(struct wthp_surface *wthp_surface,
		     struct wthp_callback *callback)
{
	struct surface *surface = wth_object_get_user_data((struct wth_object *)wthp_surface);
        fprintf(stderr, "surface %p callback(%p)\n",
                wthp_surface, callback);

        surface->cb = callback;
}

static void
surface_handle_set_opaque_region(struct wthp_surface *wthp_surface,
				 struct wthp_region *region)
{
        fprintf(stderr, "surface %p set_opaque_region(%p)\n",
                wthp_surface, region);
}

static void
surface_handle_set_input_region(struct wthp_surface *wthp_surface,
				 struct wthp_region *region)
{
        fprintf(stderr, "surface %p set_input_region(%p)\n",
                wthp_surface, region);
}

static void
surface_handle_commit(struct wthp_surface *wthp_surface)
{
	struct surface *surface = wth_object_get_user_data((struct wth_object *)wthp_surface);
        fprintf(stderr, "commit %p\n",
                wthp_surface);

        wthp_callback_send_done(surface->cb, surface->ivi_id);
	wthp_callback_free(surface->cb);
}

static void
surface_handle_set_buffer_transform(struct wthp_surface *wthp_surface,
				    int32_t transform)
{
        fprintf(stderr, "surface %p et_buffer_transform(%d)\n",
                wthp_surface, transform);
}

static void
surface_handle_set_buffer_scale(struct wthp_surface *wthp_surface,
				int32_t scale)
{
        fprintf(stderr, "surface %p set_buffer_scale(%d)\n",
                wthp_surface, scale);
}

static void
surface_handle_damage_buffer(struct wthp_surface *wthp_surface,
			     int32_t x, int32_t y, int32_t width, int32_t height)
{
        fprintf(stderr, "surface %p damage_buffer(%d, %d, %d, %d)\n",
                wthp_surface, x, y, width, height);
}

static const struct wthp_surface_interface surface_implementation = {
	surface_handle_destroy,
	surface_handle_attach,
	surface_handle_damage,
	surface_handle_frame,
	surface_handle_set_opaque_region,
	surface_handle_set_input_region,
	surface_handle_commit,
	surface_handle_set_buffer_transform,
	surface_handle_set_buffer_scale,
	surface_handle_damage_buffer
};

/* END wthp_cwsurfaceregion implementation */

/* BEGIN wthp_region implementation */

static void
buffer_handle_destroy(struct wthp_buffer *wthp_buffer)
{
	struct buffer *buf = wth_object_get_user_data((struct wth_object *)wthp_buffer);

	fprintf(stderr, "buffer %p destroy\n", buf->obj);

	wthp_buffer_free(wthp_buffer);
	wl_list_remove(&buf->link);
//	free(buf->data);
	free(buf);
}

static const struct wthp_buffer_interface buffer_implementation = {
	buffer_handle_destroy
};

/* END wthp_region implementation */

/* BEGIN wthp_blob_factory implementation */

static void
blob_factory_create_buffer(struct wthp_blob_factory *blob_factory,
			   struct wthp_buffer *wthp_buffer, uint32_t data_sz, void *data,
			   int32_t width, int32_t height, int32_t stride, uint32_t format)
{
	fprintf(stderr, "wthp_blob_factory %p create_buffer(%p, %d, %p, %d, %d, %d, %d)\n",
		blob_factory, wthp_buffer, data_sz, data, width, height, stride, format);

	struct blob_factory *blob = wth_object_get_user_data((struct wth_object *)blob_factory);
	struct buffer *buffer;

	buffer = zalloc(sizeof *buffer);
	if (!buffer) {
		client_post_out_of_memory(blob->client);
		return;
	}

	wl_list_insert(&blob->client->buffer_list, &buffer->link);

	buffer->data_sz = data_sz;
	buffer->data = data;
	buffer->width = width;
	buffer->height = height;
	buffer->stride = stride;
	buffer->format = format;
	buffer->obj = wthp_buffer;

	wthp_buffer_set_interface(wthp_buffer, &buffer_implementation, buffer);
}

static const struct wthp_blob_factory_interface blob_factory_implementation = {
	blob_factory_create_buffer
};

static void
client_bind_blob_factory(struct client *c, struct wthp_blob_factory *obj)
{
	struct blob_factory *blob;

	blob = zalloc(sizeof *blob);
	if (!blob) {
		client_post_out_of_memory(c);
		return;
	}

	blob->obj = obj;
	blob->client = c;
	wl_list_insert(&c->compositor_list, &blob->link);

	wthp_blob_factory_set_interface(obj, &blob_factory_implementation,
					 blob);
	fprintf(stderr, "client %p bound wthp_blob_factory\n", c);
}

static void
wthp_ivi_surface_destroy(struct wthp_ivi_surface *ivi_surface)
{
	struct ivisurface *ivisurf =
		wth_object_get_user_data((struct wth_object *)ivi_surface);
	free(ivisurf);
}

static const struct wthp_ivi_surface_interface ivi_surface_implementation = {
	wthp_ivi_surface_destroy
};

static void
wthp_ivi_application_surface_create(struct wthp_ivi_application *ivi_application, uint32_t ivi_id,
		   struct wthp_surface *wthp_surface, struct wthp_ivi_surface *obj)
{
	fprintf(stderr, "wthp_ivi_application %p surface_create(%d, %p, %p)\n",
		ivi_application, ivi_id, wthp_surface, obj);
	struct surface *surface = wth_object_get_user_data((struct wth_object *)wthp_surface);
	struct application *app = wth_object_get_user_data((struct wth_object *)ivi_application);

	struct ivisurface *ivisurf;

	ivisurf = zalloc(sizeof *ivisurf);
	if (!ivisurf) {
		return;
	}

	surface->ivi_id = ivi_id;
	ivisurf->obj = obj;
	ivisurf->surf = surface;

	wthp_ivi_surface_set_interface(obj, &ivi_surface_implementation,
				  ivisurf);
}

static const struct wthp_ivi_application_interface wthp_ivi_application_implementation = {
	wthp_ivi_application_surface_create
};

static void
client_bind_wthp_ivi_application(struct client *c, struct wthp_ivi_application *obj)
{
	struct application *app;

	app = zalloc(sizeof *app);
	if (!app) {
		client_post_out_of_memory(c);
		return;
	}

	app->obj = obj;
	app->client = c;
	wl_list_insert(&c->compositor_list, &app->link);

	wthp_ivi_application_set_interface(obj, &wthp_ivi_application_implementation,
					 app);
	fprintf(stderr, "client %p bound wthp_ivi_application\n", c);
}
/* END wthp_blob_factory implementation */

/* BEGIN wthp_region implementation */

static void
region_destroy(struct region *region)
{
	fprintf(stderr, "region %p destroy\n", region->obj);

	wthp_region_free(region->obj);
	wl_list_remove(&region->link);
	free(region);
}

static void
region_handle_destroy(struct wthp_region *wthp_region)
{
	struct region *region = wth_object_get_user_data((struct wth_object *)wthp_region);

	assert(wthp_region == region->obj);

	region_destroy(region);
}

static void
region_handle_add(struct wthp_region *wthp_region,
		  int32_t x, int32_t y, int32_t width, int32_t height)
{
	fprintf(stderr, "region %p add(%d, %d, %d, %d)\n",
		wthp_region, x, y, width, height);
}

static void
region_handle_subtract(struct wthp_region *wthp_region,
		       int32_t x, int32_t y,
		       int32_t width, int32_t height)
{
	fprintf(stderr, "region %p subtract(%d, %d, %d, %d)\n",
		wthp_region, x, y, width, height);
}

static const struct wthp_region_interface region_implementation = {
	region_handle_destroy,
	region_handle_add,
	region_handle_subtract
};

/* END wthp_region implementation */

/* BEGIN wthp_compositor implementation */

static void
compositor_destroy(struct compositor *comp)
{
	fprintf(stderr, "%s: %p\n", __func__, comp->obj);

	wthp_compositor_free(comp->obj);
	wl_list_remove(&comp->link);
	free(comp);
}

static void
compositor_handle_create_surface(struct wthp_compositor *compositor,
				 struct wthp_surface *id)
{
	struct compositor *comp = wth_object_get_user_data((struct wth_object *)compositor);
	struct surface *surface;

	fprintf(stderr, "client %p create surface %p\n",
		comp->client, id);

	surface = zalloc(sizeof *surface);
	if (!surface) {
		client_post_out_of_memory(comp->client);
		return;
	}

	surface->obj = id;
	wl_list_insert(&comp->client->surface_list, &surface->link);

	wthp_surface_set_interface(id, &surface_implementation, surface);
}

static void
compositor_handle_create_region(struct wthp_compositor *compositor,
				struct wthp_region *id)
{
	struct compositor *comp = wth_object_get_user_data((struct wth_object *)compositor);
	struct region *region;

	fprintf(stderr, "client %p create region %p\n",
		comp->client, id);

	region = zalloc(sizeof *region);
	if (!region) {
		client_post_out_of_memory(comp->client);
		return;
	}

	region->obj = id;
	wl_list_insert(&comp->client->region_list, &region->link);

	wthp_region_set_interface(id, &region_implementation, region);
}

static const struct wthp_compositor_interface compositor_implementation = {
	compositor_handle_create_surface,
	compositor_handle_create_region
	/* XXX: protocol is missing destructor */
};

static void
client_bind_compositor(struct client *c, struct wthp_compositor *obj)
{
	struct compositor *comp;

	comp = zalloc(sizeof *comp);
	if (!comp) {
		client_post_out_of_memory(c);
		return;
	}

	comp->obj = obj;
	comp->client = c;
	wl_list_insert(&c->compositor_list, &comp->link);

	wthp_compositor_set_interface(obj, &compositor_implementation,
				      comp);
	fprintf(stderr, "client %p bound wthp_compositor\n", c);
}

/* END wthp_compositor implementation */

/* BEGIN wthp_registry implementation */

static void
registry_destroy(struct registry *reg)
{
	fprintf(stderr, "%s: %p\n", __func__, reg->obj);

	wthp_registry_free(reg->obj);
	wl_list_remove(&reg->link);
	free(reg);
}

static void
registry_handle_destroy(struct wthp_registry *registry)
{
	struct registry *reg = wth_object_get_user_data((struct wth_object *)registry);

	registry_destroy(reg);
}

static void
registry_handle_bind(struct wthp_registry *registry,
		     uint32_t name,
		     struct wth_object *id,
		     const char *interface,
		     uint32_t version)
{
	struct registry *reg = wth_object_get_user_data((struct wth_object *)registry);

	/* XXX: we could use a database of globals instead of hardcoding them */

	if (strcmp(interface, "wthp_compositor") == 0) {
		/* XXX: check version against limits */
		/* XXX: check that name and interface match */
		client_bind_compositor(reg->client, (struct wthp_compositor *)id);
	} else if (strcmp(interface, "wthp_blob_factory") == 0) {
		client_bind_blob_factory(reg->client, (struct wthp_blob_factory *)id);
	} else if (strcmp(interface, "wthp_ivi_application") == 0) {
		client_bind_wthp_ivi_application(reg->client, (struct wthp_ivi_application *)id);
	} else {
		wth_object_post_error((struct wth_object *)registry, 0,
				      "%s: unknown name %u", __func__, name);
		wth_object_delete(id);
	}
}

const struct wthp_registry_interface registry_implementation = {
	registry_handle_destroy,
	registry_handle_bind
};

/* END wthp_registry implementation */

/* BEGIN wth_display implementation
 * This belongs in Waltham instead.
 */

static void
display_handle_client_version(struct wth_display *wth_display,
			      uint32_t client_version)
{
	wth_object_post_error((struct wth_object *)wth_display, 0,
			      "unimplemented: %s", __func__);
}

static void
display_handle_sync(struct wth_display * wth_display, struct wthp_callback * callback)
{
	struct client *c = wth_object_get_user_data((struct wth_object *)wth_display);

	fprintf(stderr, "Client %p requested wth_display.sync\n", c);
	wthp_callback_send_done(callback, 0);
	wthp_callback_free(callback);
}

static void
display_handle_get_registry(struct wth_display *wth_display,
			    struct wthp_registry *registry)
{
	struct client *c = wth_object_get_user_data((struct wth_object *)wth_display);
	struct registry *reg;

	reg = zalloc(sizeof *reg);
	if (!reg) {
		client_post_out_of_memory(c);
		return;
	}

	reg->obj = registry;
	reg->client = c;
	wl_list_insert(&c->registry_list, &reg->link);
	wthp_registry_set_interface(registry,
				    &registry_implementation, reg);

	/* XXX: advertise our globals */
	wthp_registry_send_global(registry, 1, "wthp_compositor", 4);
	wthp_registry_send_global(registry, 1, "wthp_blob_factory", 4);
	wthp_registry_send_global(registry, 1, "wthp_ivi_application", 1);
}

static const struct wth_display_interface display_implementation = {
	display_handle_client_version,
	display_handle_sync,
	display_handle_get_registry
};

/* END wth_display implementation */

static void
client_destroy(struct client *c)
{
	struct region *region;
	struct compositor *comp;
	struct registry *reg;
	struct surface *surface;

	fprintf(stderr, "Client %p disconnected.\n", c);

	/* clean up remaining client resources in case the client
	 * did not.
	 */
	wl_list_last_until_empty(region, &c->region_list, link)
		region_destroy(region);

	wl_list_last_until_empty(comp, &c->compositor_list, link)
		compositor_destroy(comp);

	wl_list_last_until_empty(reg, &c->registry_list, link)
		registry_destroy(reg);

	wl_list_last_until_empty(surface, &c->surface_list, link)
		surface_destroy(surface);

	wl_list_remove(&c->link);
	watch_ctl(&c->conn_watch, EPOLL_CTL_DEL, 0);
	wth_connection_destroy(c->connection);
	free(c);
}

static void
connection_handle_data(struct watch *w, uint32_t events)
{
	struct client *c = container_of(w, struct client, conn_watch);
	int ret;

	if (events & EPOLLERR) {
		fprintf(stderr, "Client %p errored out.\n", c);
		client_destroy(c);

		return;
	}

	if (events & EPOLLHUP) {
		fprintf(stderr, "Client %p hung up.\n", c);
		client_destroy(c);

		return;
	}

	if (events & EPOLLOUT) {
		ret = wth_connection_flush(c->connection);
		if (ret == 0)
			watch_ctl(&c->conn_watch, EPOLL_CTL_MOD, EPOLLIN);
		else if (ret < 0 && errno != EAGAIN){
			fprintf(stderr, "Client %p flush error.\n", c);
			client_destroy(c);

			return;
		}
	}

	if (events & EPOLLIN) {
		ret = wth_connection_read(c->connection);
		if (ret < 0) {
			fprintf(stderr, "Client %p read error.\n", c);
			client_destroy(c);

			return;
		}

		ret = wth_connection_dispatch(c->connection);
		if (ret < 0 && errno != EPROTO) {
			fprintf(stderr, "Client %p dispatch error.\n", c);
			client_destroy(c);

			return;
		}
	}
}

static struct client *
client_create(struct server *srv, struct wth_connection *conn)
{
	struct client *c;
	struct wth_display *disp;

	c = zalloc(sizeof *c);
	if (!c)
		return NULL;

	c->server = srv;
	c->connection = conn;

	c->conn_watch.server = srv;
	c->conn_watch.fd = wth_connection_get_fd(conn);
	c->conn_watch.cb = connection_handle_data;
	if (watch_ctl(&c->conn_watch, EPOLL_CTL_ADD, EPOLLIN) < 0) {
		free(c);
		return NULL;
	}

	fprintf(stderr, "Client %p connected.\n", c);

	wl_list_insert(&srv->client_list, &c->link);

	wl_list_init(&c->registry_list);
	wl_list_init(&c->compositor_list);
	wl_list_init(&c->region_list);
	wl_list_init(&c->surface_list);
	wl_list_init(&c->blob_factory_list);
	wl_list_init(&c->buffer_list);

	/* XXX: this should be inside Waltham */
	disp = wth_connection_get_display(c->connection);
	wth_display_set_interface(disp, &display_implementation, c);

	return c;
}

static void
server_flush_clients(struct server *srv)
{
	struct client *c, *tmp;
	int ret;

	wl_list_for_each_safe(c, tmp, &srv->client_list, link) {
		/* Flush out buffered requests. If the Waltham socket is
		 * full, poll it for writable too.
		 */
		ret = wth_connection_flush(c->connection);
		if (ret < 0 && errno == EAGAIN) {
			watch_ctl(&c->conn_watch, EPOLL_CTL_MOD, EPOLLIN | EPOLLOUT);
		} else if (ret < 0) {
			perror("Connection flush failed");
			client_destroy(c);
		}
	}
}

static void
server_accept_client(struct server *srv)
{
	struct client *client;
	struct wth_connection *conn;
	struct sockaddr_in addr;
	socklen_t len;

	len = sizeof addr;
	conn = wth_accept(srv->listen_fd, (struct sockaddr *)&addr, &len);
	if (!conn) {
		fprintf(stderr, "Failed to accept a connection.\n");

		return;
	}

	client = client_create(srv, conn);
	if (!client) {
		fprintf(stderr, "Failed client_create().\n");

		return;
	}
}

static void
listen_socket_handle_data(struct watch *w, uint32_t events)
{
	struct server *srv = container_of(w, struct server, listen_watch);

	if (events & EPOLLERR) {
		fprintf(stderr, "Listening socket errored out.\n");
		srv->running = false;

		return;
	}

	if (events & EPOLLHUP) {
		fprintf(stderr, "Listening socket hung up.\n");
		srv->running = false;

		return;
	}

	if (events & EPOLLIN)
		server_accept_client(srv);
}

static void
mainloop(struct server *srv)
{
	struct epoll_event ee[MAX_EPOLL_WATCHES];
	struct watch *w;
	int count;
	int i;

	srv->running = true;

	while (srv->running) {
		/* Run any idle tasks at this point. */

		server_flush_clients(srv);

		/* Wait for events or signals */
		count = epoll_wait(srv->epoll_fd,
				   ee, ARRAY_LENGTH(ee), -1);
		if (count < 0 && errno != EINTR) {
			perror("Error with epoll_wait");
			break;
		}

		/* Handle all fds, both the listening socket
		 * (see listen_socket_handle_data()) and clients
		 * (see connection_handle_data()).
		 */
		for (i = 0; i < count; i++) {
			w = ee[i].data.ptr;
			w->cb(w, ee[i].events);
		}
	}
}

static int
server_listen(uint16_t tcp_port)
{
	int fd;
	int reuse = 1;
	struct sockaddr_in addr;

	fd = socket(AF_INET, SOCK_STREAM, 0);

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(tcp_port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof reuse);

	if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
		fprintf(stderr, "Failed to bind to port %d", tcp_port);
		close(fd);
		return -1;
	}

	if (listen(fd, 1024) < 0) {
		fprintf(stderr, "Failed to listen to port %d", tcp_port);
		close (fd);
		return -1;
	}

	return fd;
}

static bool *signal_int_handler_run_flag;

static void
signal_int_handler(int signum)
{
	if (!*signal_int_handler_run_flag)
		abort();

	*signal_int_handler_run_flag = false;
}

static void
set_sigint_handler(bool *running)
{
	struct sigaction sigint;

	signal_int_handler_run_flag = running;
	sigint.sa_handler = signal_int_handler;
	sigemptyset(&sigint.sa_mask);
	sigint.sa_flags = SA_RESETHAND;
	sigaction(SIGINT, &sigint, NULL);
}

int
main(int arcg, char *argv[])
{
	struct server srv = { 0 };
	struct client *c;
	uint16_t tcp_port = 34400;

	set_sigint_handler(&srv.running);

	wl_list_init(&srv.client_list);

	srv.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (srv.epoll_fd == -1) {
		perror("Error on epoll_create1");
		exit(1);
	}

	srv.listen_fd = server_listen(tcp_port);
	if (srv.listen_fd < 0) {
		perror("Error setting up listening socket");
		exit(1);
	}

	srv.listen_watch.server = &srv;
	srv.listen_watch.cb = listen_socket_handle_data;
	srv.listen_watch.fd = srv.listen_fd;
	if (watch_ctl(&srv.listen_watch, EPOLL_CTL_ADD, EPOLLIN) < 0) {
		perror("Error setting up listen polling");
		exit(1);
	}

	printf("Waltham server listening on TCP port %u...\n",
	       tcp_port);

	mainloop(&srv);

	/* destroy all things */
	wl_list_last_until_empty(c, &srv.client_list, link)
		client_destroy(c);

	close(srv.listen_fd);
	close(srv.epoll_fd);

	return 0;
}
