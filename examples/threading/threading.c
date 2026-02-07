#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// Optional: use these functions to add debug or error prints to your application
#define DEBUG_LOG(msg,...)
//#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

void* threadfunc(void* thread_param)
{

    // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
    // hint: use a cast like the one below to obtain thread arguments from your parameter
    struct thread_data* thread_func_args = (struct thread_data *) thread_param;
    /*waiting*/
    usleep(thread_func_args->wait_to_obtain_ms * 1000);

    /*obtaining mutex*/
    pthread_mutex_lock (thread_func_args->mutex);
    thread_func_args->thread_complete_success = true;

    /*waiting*/
    usleep(thread_func_args->wait_to_release_ms * 1000);

    /*release mutex*/
    pthread_mutex_unlock(thread_func_args->mutex);
    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    /**
     * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */
     pthread_t *ref_thread = thread;
     
    int ret;
  
    struct thread_data *thread_info = malloc(sizeof(struct thread_data));
    
    if(thread_info == NULL){
	return false;
    }
    thread_info->mutex = mutex;
    thread_info->wait_to_obtain_ms = wait_to_obtain_ms;
    thread_info->wait_to_release_ms = wait_to_release_ms;
    thread_info->thread_complete_success = false;

     ret = pthread_create(ref_thread, NULL, threadfunc, (void *)thread_info);
     if(ret != 0) {
	free(thread_info);
	errno = ret;
	perror("pthread_create);
	return false;
    }  
    return true;
}

