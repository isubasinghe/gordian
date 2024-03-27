# 0 "out_copy.c"
# 0 "<built-in>"
# 0 "<command-line>"
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 0 "<command-line>" 2
# 1 "out_copy.c"


typedef unsigned long uint64_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef uint64_t size_t;
typedef uint64_t uintptr_t;


typedef unsigned char bool;
# 19 "out_copy.c"
void assert(bool b);



void *memcpy(void *dest, const void *src, size_t n);


typedef unsigned int sel4cp_channel;
void sel4cp_notify(sel4cp_channel ch);
void sel4cp_notify_delayed(sel4cp_channel ch);
# 51 "out_copy.c"
typedef struct buff_desc {
    uintptr_t phys_or_offset;
    uint16_t len;
    void *cookie;
} buff_desc_t;


typedef struct ring_buffer {
    uint32_t head;
    uint32_t tail;
    buff_desc_t buffers[512];
    uint32_t size;
    bool consumer_signalled;
} ring_buffer_t;


typedef struct ring_handle {
    ring_buffer_t *free_ring;
    ring_buffer_t *used_ring;
} ring_handle_t;
# 79 "out_copy.c"
static inline bool ring_empty(ring_buffer_t *ring)
{
    return (ring->head == ring->tail);
}
# 91 "out_copy.c"
static inline bool ring_full(ring_buffer_t *ring)
  // requires ring->size >= 1
  // ensures return == {retbody}
{
    return (((ring->head + 1) % ring->size) == ring->tail);
}
# 103 "out_copy.c"
static inline uint32_t ring_size(ring_buffer_t *ring)
{
    return (((ring->head + ring->size) - ring->tail) % ring->size);
}
# 116 "out_copy.c"
static inline int enqueue(ring_buffer_t *ring, buff_desc_t buffer)
{
    if (ring_full(ring)) return -1;

    ring->buffers[ring->head].phys_or_offset = buffer.phys_or_offset;
    ring->buffers[ring->head].len = buffer.len;
    ring->buffers[ring->head].cookie = buffer.cookie;
    if (0) ;
    ring->head = (ring->head + 1) % ring->size;

    return 0;
}

# 135 "out_copy.c"
static inline buff_desc_t dequeue(ring_buffer_t *ring)
{
    if (ring_empty(ring)) assert(0);

    buff_desc_t buffer;
    buffer.phys_or_offset = ring->buffers[ring->tail].phys_or_offset;
    buffer.len = ring->buffers[ring->tail].len;
    buffer.cookie = ring->buffers[ring->tail].cookie;
    if (0) ;
    ring->tail = (ring->tail + 1) % ring->size;

    return buffer;
}
# 155 "out_copy.c"
static inline int enqueue_free(ring_handle_t *ring, buff_desc_t buffer)
{

    ring_buffer_t *local_ring = ring->free_ring;
    return enqueue(local_ring, buffer);
}
# 168 "out_copy.c"
static inline int enqueue_used(ring_handle_t *ring, buff_desc_t buffer)
{

    ring_buffer_t *local_ring = ring->used_ring;
    return enqueue(local_ring, buffer);
}
# 181 "out_copy.c"
static inline buff_desc_t dequeue_free(ring_handle_t *ring)
{
    ring_buffer_t *local_ring = ring->free_ring;
    ring_buffer_t *other_ring = ring->used_ring;
    return dequeue(local_ring);
}
# 194 "out_copy.c"
static inline buff_desc_t dequeue_used(ring_handle_t *ring)
{
    ring_buffer_t *local_ring = ring->used_ring;
    ring_buffer_t *other_ring = ring->free_ring;
    return dequeue(local_ring);
}
# 208 "out_copy.c"
void ring_init(ring_handle_t *ring, ring_buffer_t *free, ring_buffer_t *used, uint32_t free_size, uint32_t used_size);
# 218 "out_copy.c"
static inline void buffers_init(ring_buffer_t *free_ring, uintptr_t base_addr, uint32_t ring_size, uint32_t buffer_size)
{
    for (int i = 0; i < ring_size - 1; i++) {
        buff_desc_t buffer = {(buffer_size * i) + base_addr, 0, ((void *) 0)};
        int err __attribute__((unused)) = enqueue(free_ring, buffer);
        assert(!err);
    }
}

static inline void request_signal(ring_buffer_t *ring_buffer)
{
    ring_buffer->consumer_signalled = 0;
    if (0) ;
}

static inline void cancel_signal(ring_buffer_t *ring_buffer)
{
    ring_buffer->consumer_signalled = 1;
    if (0) ;
}






static inline bool require_signal(ring_buffer_t *ring_buffer)
{
    return !ring_buffer->consumer_signalled;
}
# 269 "out_copy.c"

ring_handle_t rx_ring_mux;
ring_handle_t rx_ring_cli;


uintptr_t rx_free_mux;
uintptr_t rx_used_mux;
uintptr_t rx_free_cli;
uintptr_t rx_used_cli;


uintptr_t mux_buffer_data_region;
uintptr_t cli_buffer_data_region;

uintptr_t uart_base;


void dirty(uintptr_t x) {
  rx_free_mux = x;
  rx_used_mux = x;
  rx_free_cli = x;
  rx_used_cli = x;
  mux_buffer_data_region = x;
  cli_buffer_data_region = x;
}

void dirty_mux_hnd(uintptr_t x) {
  rx_ring_mux.free_ring = (ring_buffer_t *)x;
  rx_ring_mux.used_ring = (ring_buffer_t *)x;
}

void dirty_cli_hnd(uintptr_t x) {
  rx_ring_cli.free_ring = (ring_buffer_t *)x;
  rx_ring_cli.used_ring = (ring_buffer_t *)x;
}

void assert_non_empty() {
}

void assert_mem_good() {
}

void assert_ring_wf(ring_buffer_t *ring) {
}

void assert_ring_non_empty(ring_buffer_t *ring) {

}

void assert_ring_distinct(void *ptr1,
    void *ptr2, void *ptr3, void *ptr4,
    void *ptr5, void *ptr6, void *ptr7, void *ptr8) {
}

void assert_fits_pointer(void *ptr) {
}

void assert_distinct() {
}

void assert_ring_full(ring_buffer_t *ring) {

}

void empty_consume(buff_desc_t buff) {
}

void test_distinct() {
}

bool rx_return_inner_inner() {

  buff_desc_t cli_buffer = dequeue_free(&rx_ring_cli);
  if (cli_buffer.phys_or_offset % 2048 || cli_buffer.phys_or_offset >= 2048 * 512) {
    empty_consume(cli_buffer);
    return 0;
  }

  buff_desc_t mux_buffer = dequeue_used(&rx_ring_mux);

  uintptr_t cli_addr = cli_buffer_data_region + cli_buffer.phys_or_offset;
  uintptr_t mux_addr = mux_buffer_data_region + mux_buffer.phys_or_offset;

  memcpy((void *)cli_addr, (void *)mux_addr, mux_buffer.len);
  cli_buffer.len = mux_buffer.len;
  mux_buffer.len = 0;

  enqueue_used(&rx_ring_cli, cli_buffer);
  enqueue_free(&rx_ring_mux, mux_buffer);

  return 1;
}

bool rx_return_inner() {
  bool enqueued = 0;
  while(1) {
    bool val = !ring_empty(rx_ring_mux.used_ring) && !ring_empty(rx_ring_cli.free_ring)
      && !ring_full(rx_ring_mux.free_ring) && !ring_full(rx_ring_cli.used_ring);
    if(val) {
      enqueued = rx_return_inner_inner() || enqueued;
    }else {
      break;
    }
  }
  return enqueued;
}

void rx_return_outer() { 
  bool reprocess = 1;
  bool enqueued = 0;

  while(reprocess) { 
    enqueued = rx_return_inner() || enqueued;

    request_signal(rx_ring_mux.used_ring);

    if (!ring_empty(rx_ring_mux.used_ring)) request_signal(rx_ring_cli.free_ring);
    else cancel_signal(rx_ring_cli.free_ring);

    reprocess = 0;

    if (!ring_empty(rx_ring_mux.used_ring) && !ring_empty(rx_ring_cli.free_ring) &&
        !ring_full(rx_ring_mux.free_ring) && !ring_full(rx_ring_cli.used_ring)) {
        cancel_signal(rx_ring_mux.used_ring);
        cancel_signal(rx_ring_cli.free_ring);
        reprocess = 1;
    }
  }

  if (enqueued && require_signal(rx_ring_cli.used_ring)) {
      cancel_signal(rx_ring_cli.used_ring);
      sel4cp_notify(1);
  }

  if (enqueued && require_signal(rx_ring_mux.free_ring)) {
      cancel_signal(rx_ring_mux.free_ring);
      sel4cp_notify_delayed(0);
  }
}

/* void rx_return(void)
{
    bool enqueued = 0;
    bool reprocess = 1;

    while (reprocess) {
        while (!ring_empty(rx_ring_mux.used_ring) && !ring_empty(rx_ring_cli.free_ring) &&
                !ring_full(rx_ring_mux.free_ring) && !ring_full(rx_ring_cli.used_ring)) {
            buff_desc_t cli_buffer, mux_buffer;
            int err;
            cli_buffer = dequeue_free(&rx_ring_cli);

            if (cli_buffer.phys_or_offset % 2048 || cli_buffer.phys_or_offset >= 2048 * 512) {
              
            } else {
                mux_buffer = dequeue_used(&rx_ring_mux);

                uintptr_t cli_addr = cli_buffer_data_region + cli_buffer.phys_or_offset;
                uintptr_t mux_addr = mux_buffer_data_region + mux_buffer.phys_or_offset;

                memcpy((void *)cli_addr, (void *)mux_addr, mux_buffer.len);
                cli_buffer.len = mux_buffer.len;
                mux_buffer.len = 0;

                err = enqueue_used(&rx_ring_cli, cli_buffer);
                assert(!err);

                err = enqueue_free(&rx_ring_mux, mux_buffer);
                assert(!err);

                enqueued = 1;
            }

        }

        request_signal(rx_ring_mux.used_ring);


        if (!ring_empty(rx_ring_mux.used_ring)) request_signal(rx_ring_cli.free_ring);
        else cancel_signal(rx_ring_cli.free_ring);

        reprocess = 0;

        if (!ring_empty(rx_ring_mux.used_ring) && !ring_empty(rx_ring_cli.free_ring) &&
            !ring_full(rx_ring_mux.free_ring) && !ring_full(rx_ring_cli.used_ring)) {
            cancel_signal(rx_ring_mux.used_ring);
            cancel_signal(rx_ring_cli.free_ring);
            reprocess = 1;
        }
    }

    if (enqueued && require_signal(rx_ring_cli.used_ring)) {
        cancel_signal(rx_ring_cli.used_ring);
        sel4cp_notify(1);
    }

    if (enqueued && require_signal(rx_ring_mux.free_ring)) {
        cancel_signal(rx_ring_mux.free_ring);
        sel4cp_notify_delayed(0);
    }
} */

void notified(sel4cp_channel ch)
{
    rx_return_outer();
}

void init(void)
{
    ring_init(&rx_ring_mux, (ring_buffer_t *)rx_free_mux, (ring_buffer_t *)rx_used_mux, 512, 512);
    ring_init(&rx_ring_cli, (ring_buffer_t *)rx_free_cli, (ring_buffer_t *)rx_used_cli, 512, 512);

    buffers_init(rx_ring_cli.free_ring, 0, 512, 2048);
}
