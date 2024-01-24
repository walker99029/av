#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#ifndef _WIN32
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <clamav.h>

#ifndef O_BINARY
#define O_BINARY 0
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <clamav.h>

#ifndef O_BINARY
#define O_BINARY 0
#endif

    /*
    * No seas cochino, piensa, no incluyas librerias que no vas a utilizar
    * No hagas las cosas por bonito, que termina quedando puerco tu programa.
    * Haz todo en orden, declara todas las variables que vas a utilizar al principio.
    * Recuerda que debes hacer para que tu programa sea optimizado.
    * No pienses que vas a hackear la NASA de ahora pa' ahorita, haz las cosas con calma.
    */

int scan_dir(char *dir_name, int depth) {

    int fd, ret;
    unsigned long int size = 0;
    unsigned int sigs      = 0;
    long double mb;
    const char *virname;
    const char *filename;
    struct cl_engine *engine;
    struct cl_scan_options options;

    DIR *dp;
    struct dirent *entry;
    struct stat statbuf;

/*Open directory*/
    if((dp = opendir(dir_name)) == -1) {
        printf("Error, Can't open dirctory: %s", dir_name);
        return 2;
    }
/**/
/*Create engine*/    
    if((ret = cl_init(CL_INIT_DEFAULT)) != CL_SUCCESS) {
       printf("cl_init() error: %s", cl_strerror(ret));
       return 2;
    }
    if(!(engine = cl_engine_new())) {
        printf("Error, can't create new engine");
        return 2;
    }
/**/
/*Load Virus Database*/
    if((ret = cl_load(cl_retdbdir(), engine, &sigs, CL_DB_STDOPT)) != CL_SUCCESS) {
        printf("cl_load() error: %s", cl_strerror(ret));
        close(fd);
        cl_engine_free(engine);
        return 2;
    }

    printf("Loading %u", sigs);
/**/
/*Compile engine*/
    if((ret = cl_engine_compile(engine)) != CL_SUCCESS) {
        printf("cl_engine_compile error: %s", cl_strerror(ret));
        close(fd);
        cl_engine_free(engine);
        return 2;
    }

    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;                           /* enable all parsers */
    options.general |= CL_SCAN_GENERAL_HEURISTICS; /* enable heuristic alert options */
/**/
/*Scan*/
    while ((entry = readdir(dp)) != NULL) {
    lstat(entry->d_name, &statbuf);
    if (S_ISDIR(statbuf.st_mode)) {
        if (strcmp(".", entry->d_name) == 0 || strcmp("..", entry->d_name) == 0)
            continue;

        printf("%*s[+] %s/\n", depth*2, "", entry->d_name);
        scan_dir(entry->d_name, depth + 1);
    } else {

    filename = entry->d_name;

    if ((fd = open(filename, O_RDONLY | O_BINARY)) == -1) {
        printf("Can't open file %s\n", argv[1]);
        return 2;
    }

    if ((ret = cl_scandesc(fd, filename, &virname, &size, engine, &options)) == CL_VIRUS) {
        printf("Virus detected: %s\n", virname);
    } else {
        if (ret == CL_CLEAN) {
            printf("%s OK", filename);
        } else {
            printf("Error: %s\n", cl_strerror(ret));
            cl_engine_free(engine);
            close(fd);
            return 2;
        }
    }
    close(fd);

        
        printf("%*s- %s\n", depth*2, "", entry->d_name);
    }
}

chdir("..");
closedir(dp);

    cl_engine_free(engine);

    mb = size * (CL_COUNT_PRECISION / 1024) / 1024.0;
    printf("Data scanned: %2.2Lf MB\n", mb);

    return ret == CL_VIRUS ? 1 : 0;
}

int scan_file(int argc, char **argv) {

    int fd, ret;
    unsigned long int size = 0;
    unsigned int sigs      = 0;
    long double mb;
    const char *virname;
    const char *filename;
    struct cl_engine *engine;
    struct cl_scan_options options;

    if (argc != 2) {
        printf("Usage: %s file\n", argv[0]);
        return 2;
    }

    filename = argv[1];

    if ((fd = open(argv[1], O_RDONLY | O_BINARY)) == -1) {
        printf("Can't open file %s\n", argv[1]);
        return 2;
    }

    if ((ret = cl_init(CL_INIT_DEFAULT)) != CL_SUCCESS) {
        printf("Can't initialize libclamav: %s\n", cl_strerror(ret));
        return 2;
    }

    if (!(engine = cl_engine_new())) {
        printf("Can't create new engine\n");
        return 2;
    }

    if ((ret = cl_load(cl_retdbdir(), engine, &sigs, CL_DB_STDOPT)) != CL_SUCCESS) {
        printf("cl_load: %s\n", cl_strerror(ret));
        close(fd);
        cl_engine_free(engine);
        return 2;
    }

    printf("Loaded %u signatures.\n", sigs);

       if ((ret = cl_engine_compile(engine)) != CL_SUCCESS) {
        printf("Database initialization error: %s\n", cl_strerror(ret));
        cl_engine_free(engine);
        close(fd);
        return 2;
    }

    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;                           /* enable all parsers */
    options.general |= CL_SCAN_GENERAL_HEURISTICS; /* enable heuristic alert options */


    if ((ret = cl_scandesc(fd, filename, &virname, &size, engine, &options)) == CL_VIRUS) {
        printf("Virus detected: %s\n", virname);
    } else {
        if (ret == CL_CLEAN) {
            printf("No virus detected.\n");
        } else {
            printf("Error: %s\n", cl_strerror(ret));
            cl_engine_free(engine);
            close(fd);
            return 2;
        }
    }
    close(fd);

    cl_engine_free(engine);

    mb = size * (CL_COUNT_PRECISION / 1024) / 1024.0;
    printf("Data scanned: %2.2Lf MB\n", mb);

    return ret == CL_VIRUS ? 1 : 0;


}

int main() {
    scan_file(/*file*/)
    scan_dir(/*directory*/);
    return 0;
}