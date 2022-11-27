/**
 * Video for Linux version 2 (V4L2) example 5 - video capture
 *
 * Based on
 * - https://linuxtv.org/downloads/v4l-dvb-apis/uapi/v4l/capture.c.html
 *
 * Kyle M. Douglass, 2018
 * kyle.m.douglass@gmail.com
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/videodev2.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <unistd.h>
#include <vector>
#include <opencv2/core/core.hpp>
#include <opencv2/highgui/highgui.hpp>

using namespace cv;

Mat mat;
std::vector<Mat> buf;
VideoWriter outputVideo("VideoTest.avi", VideoWriter::fourcc('M', 'J', 'P', 'G'), 25.0, Size(640, 480));

#define MJPEG
#define IMAGEWIDTH 640
#define IMAGEHEIGHT 480

void usage(const char *prog){
	fprintf(stderr, "%s -h, show this usage\n", prog);
	fprintf(stderr, "%s [-c frame count, default is 10]\n", prog);
	exit(1);
}

void Delay(int time){ 
    clock_t now = clock(); 
    while(clock() - now < time); 
} 


static const char DEVICE[] = "/dev/video0";

int count = 10; // Record 10 frames, default
int frame_seq; // sequence of frame file
int frame_total;
int frame_idx = 1;
int fd;
struct buf {
  void *start;
  size_t length;
} *buffers;
unsigned int num_buffers;
struct v4l2_requestbuffers reqbuf = {0};

/**
 * Wrapper around ioctl calls.
 */
static int xioctl(int fd, int request, void *arg) {
  int r;

  do {
    r = ioctl(fd, request, arg);
  } while (-1 == r && EINTR == errno);

  return r;
}

static void init_mmap(void) {
  reqbuf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  reqbuf.memory = V4L2_MEMORY_MMAP;
  reqbuf.count = 5;
  if (-1 == xioctl(fd, VIDIOC_REQBUFS, &reqbuf)) {
    perror("VIDIOC_REQBUFS");
    exit(errno);
  }

  if (reqbuf.count < 2){
    printf("Not enough buffer memory\n");
    exit(EXIT_FAILURE);
  }

  buffers = (struct buf *) calloc(reqbuf.count, sizeof(*buffers));
  assert(buffers != NULL);

  num_buffers = reqbuf.count;
  
  // Create the buffer memory maps
  struct v4l2_buffer buffer;
  for (unsigned int i = 0; i < reqbuf.count; i++) {
    memset(&buffer, 0, sizeof(buffer));
    buffer.type = reqbuf.type;
    buffer.memory = V4L2_MEMORY_MMAP;
    buffer.index = i;

    // Note: VIDIOC_QUERYBUF, not VIDIOC_QBUF, is used here!
    if (-1 == xioctl(fd, VIDIOC_QUERYBUF, &buffer)) {
      perror("VIDIOC_QUERYBUF");
      exit(errno);
    }

    buffers[i].length = buffer.length;
    buffers[i].start = mmap(
      NULL,
      buffer.length,
      PROT_READ | PROT_WRITE,
      MAP_SHARED,
      fd,
      buffer.m.offset
    );

    if (MAP_FAILED == buffers[i].start) {
      perror("mmap");
      exit(errno);
    }

    printf("mmap buffer[%u] addr: %p, length: %zu, end: %p\n", i, buffers[i].start, buffers[i].length, ((char *) buffers[i].start) + buffers[i].length);
  }
    printf("mat addr: %p\n", &mat);
}

static void init_device() {
  struct v4l2_fmtdesc fmtdesc = {0};
  fmtdesc.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;

  // Get the format with the largest index and use it
  while(0 == xioctl(fd, VIDIOC_ENUM_FMT, &fmtdesc)) {
#ifdef MJPEG
    if(0 == strcmp((char *)fmtdesc.description, "Motion-JPEG"))
	    break;
#endif
    fmtdesc.index++;
  }
  printf("\nUsing format: %s\n", fmtdesc.description);
  
  struct v4l2_format fmt = {0};
  fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;

  fmt.fmt.pix.width = IMAGEWIDTH;
  fmt.fmt.pix.height = IMAGEHEIGHT;
  fmt.fmt.pix.pixelformat = fmtdesc.pixelformat;
  fmt.fmt.pix.field = V4L2_FIELD_NONE;

  if (-1 == xioctl(fd, VIDIOC_S_FMT, &fmt)) {
    perror("VIDIOC_S_FMT");
    exit(errno);
  }

  char format_code[5];
  strncpy(format_code, (char*)&fmt.fmt.pix.pixelformat, 5);
  printf(
    "Set format:\n"
    " Width: %d\n"
    " Height: %d\n"
    " Pixel format: %s\n"
    " Field: %d\n\n",
    fmt.fmt.pix.width,
    fmt.fmt.pix.height,
    format_code,
    fmt.fmt.pix.field
  );

  init_mmap();
}

static void start_capturing(void) {
  enum v4l2_buf_type type;

  struct v4l2_buffer buffer;
  for (unsigned int i = 0; i < num_buffers; i++) {
    /* Note that we set bytesused = 0, which will set it to the buffer length
     * See
     * - https://www.linuxtv.org/downloads/v4l-dvb-apis-new/uapi/v4l/vidioc-qbuf.html?highlight=vidioc_qbuf#description
     * - https://www.linuxtv.org/downloads/v4l-dvb-apis-new/uapi/v4l/buffer.html#c.v4l2_buffer
     */
    memset(&buffer, 0, sizeof(buffer));
    buffer.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buffer.memory = V4L2_MEMORY_MMAP;
    buffer.index = i;

    // Enqueue the buffer with VIDIOC_QBUF
    if (-1 == xioctl(fd, VIDIOC_QBUF, &buffer)) {
      perror("VIDIOC_QBUF");
      exit(errno);
    }
  }

  type = V4L2_BUF_TYPE_VIDEO_CAPTURE;

  if (-1 == xioctl(fd, VIDIOC_STREAMON, &type)) {
    perror("VIDIOC_STREAMON");
    exit(errno);
  }
  
}

static void stop_capturing(void) {
  enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;

  if (-1 == xioctl(fd, VIDIOC_STREAMOFF, &type)) {
    perror("VIDIOC_STREAMOFF");
    exit(errno);
  }
}

/**
 * process the buffer
 */
static void process_image(void * pBuffer, const int byte_cnt) {
  char frame_raw_file[32] = {0};
  char frame_raw_file_fmt[32] = {0};

#ifdef MJPEG
  if(frame_idx <= 9){
	strcpy(frame_raw_file_fmt, "frame00000000%d.jpg");
  } else if(frame_idx <= 99){
	strcpy(frame_raw_file_fmt, "frame0000000%d.jpg");
  } else if(frame_idx <= 999){
	strcpy(frame_raw_file_fmt, "frame000000%d.jpg");
  } else if(frame_idx <= 9999){
	strcpy(frame_raw_file_fmt, "frame00000%d.jpg");
  } else if(frame_idx <= 99999){
	strcpy(frame_raw_file_fmt, "frame0000%d.jpg");
  } else if(frame_idx <= 999999){
	strcpy(frame_raw_file_fmt, "frame000%d.jpg");
  } else if(frame_idx <= 9999999){
	strcpy(frame_raw_file_fmt, "frame00%d.jpg");
  } else if(frame_idx <= 99999999){
	strcpy(frame_raw_file_fmt, "frame0%d.jpg");
  } else if(frame_idx <= 999999999){
	strcpy(frame_raw_file_fmt, "frame%d.jpg");
  }
  sprintf(frame_raw_file, frame_raw_file_fmt, frame_idx);
#else
  if(frame_idx <= 9){
	strcpy(frame_raw_file_fmt, "frame00000000%d.raw");
  } else if(frame_idx <= 99){
	strcpy(frame_raw_file_fmt, "frame0000000%d.raw");
  } else if(frame_idx <= 999){
	strcpy(frame_raw_file_fmt, "frame000000%d.raw");
  } else if(frame_idx <= 9999){
	strcpy(frame_raw_file_fmt, "frame00000%d.raw");
  } else if(frame_idx <= 99999){
	strcpy(frame_raw_file_fmt, "frame0000%d.raw");
  } else if(frame_idx <= 999999){
	strcpy(frame_raw_file_fmt, "frame000%d.raw");
  } else if(frame_idx <= 9999999){
	strcpy(frame_raw_file_fmt, "frame00%d.raw");
  } else if(frame_idx <= 99999999){
	strcpy(frame_raw_file_fmt, "frame0%d.raw");
  } else if(frame_idx <= 999999999){
	strcpy(frame_raw_file_fmt, "frame%d.raw");
  }
  sprintf(frame_raw_file, frame_raw_file_fmt, frame_idx);
#endif

  /* show bytes
  for(int i = 0; i < byte_cnt; i++){
  	printf("%d ", *((char *) pBuffer + i));
  }
  printf("\n");
  */

#ifdef MJPEG
  Mat rawData(1, byte_cnt, CV_8SC1, pBuffer);
  mat = imdecode(rawData, IMREAD_ANYDEPTH | IMREAD_ANYCOLOR);
  buf.push_back(mat.clone());
#endif

  /*
  FILE *frame_raw = fopen(frame_raw_file, "w+");
  assert(frame_raw != NULL);

  fwrite(pBuffer, 1, byte_cnt, frame_raw);

  fclose(frame_raw);
  */

  frame_idx++;
}

/**
 * Readout a frame from the buffers.
 */
static int read_frame(void) {
  struct v4l2_buffer buffer;
  memset(&buffer, 0, sizeof(buffer));
  buffer.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  buffer.memory = V4L2_MEMORY_MMAP;

  // Dequeue a buffer
  if (-1 == xioctl(fd, VIDIOC_DQBUF, &buffer)) {
    switch(errno) {
    case EAGAIN:
      // No buffer in the outgoing queue
      return 0;
    case EIO:
      // fall through
    default:
      perror("VIDIOC_DQBUF");
      exit(errno);
    }
  }

  assert(buffer.index < num_buffers);

  process_image(buffers[buffer.index].start, buffer.bytesused);

#ifdef MJPEG
  imshow("live" , mat);
  if((waitKey(1)) == 'q')
	exit(0);
#endif

  // Enqueue the buffer again
  if (-1 == xioctl(fd, VIDIOC_QBUF, &buffer)) {
    perror("VIDIOC_QBUF");
    exit(errno);
  }

  return 1;
}

/**
 * Poll the device until it is ready for reading.
 *
 * See https://www.gnu.org/software/libc/manual/html_node/Waiting-for-I_002fO.html
 */
static void main_loop(void) {

  frame_total = count;
  while(frame_total-- > 0) {

    fd_set fds;
    struct timeval tv;
    int r;
    for (;;) {
      // Clear the set of file descriptors to monitor, then add the fd for our device
      FD_ZERO(&fds);
      FD_SET(fd, &fds);

      // Set the timeout
      tv.tv_sec = 2;
      tv.tv_usec = 0;

      /**
       * Arguments are
       * - number of file descriptors
       * - set of read fds
       * - set of write fds
       * - set of except fds
       * - timeval struct
       * 
       * According to the man page for select, "nfds should be set to the highest-numbered file
       * descriptor in any of the three sets, plus 1."
       */
      r = select(fd + 1, &fds, NULL, NULL, &tv);

      if (-1 == r) {
        if (EINTR == errno)
          continue;

	perror("select");
	exit(errno);
      }

      if (0 == r) {
        fprintf (stderr, "select timeout\n");
        exit(EXIT_FAILURE);
      }

      if (read_frame())
	// Go to next iterartion of fhe while loop; 0 means no frame is ready in the outgoing queue.
	break;

    }
  }
  
}

int main(int argc, char *argv[]) {

  if(argc > 3)
	  usage(argv[0]);

  if(2 == argc){
	    usage(argv[0]);
  }

  if(3 == argc){
	if(0 == strcmp(argv[1], "-c"))
		count = (int) strtol(argv[2], NULL, 10);
	else 
		 usage(argv[0]);
  }
  
  // Open the device file
  fd = open(DEVICE, O_RDWR);
  if (fd < 0) {
    perror(DEVICE);
    return errno;
  }

  init_device();

  start_capturing();

  main_loop();
  
  stop_capturing();  
  
  // Cleanup
  for (unsigned int i = 0; i < reqbuf.count; i++)
    munmap(buffers[i].start, buffers[i].length);
  free(buffers);
  close(fd);

 #ifdef RAW2JPG
  char frame_cnt_str[16] = {0};
  sprintf(frame_cnt_str, "%u", count);
  char * const args[] = {"./raw2jpg.sh", frame_cnt_str, NULL};
  execv("./raw2jpg.sh", args);
 #endif

  Delay(5*1000000);

  /* Write late*/
  for (int i=0; i<buf.size(); i++)
    outputVideo.write(buf[i]);

  return 0;
}