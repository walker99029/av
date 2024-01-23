#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

int main(int argc, char **argv) {
    /*
    * No seas cochino, piensa, no incluyas librerias que no vas a utilizar
    * No hagas las cosas por bonito, que termina quedando puerco tu programa.
    * Haz todo en orden, declara todas las variables que vas a utilizar al principio.
    * Recuerda que debes hacer para que tu programa sea optimizado.
    * No pienses que vas a hackear la NASA de ahora pa' ahorita, haz las cosas con calma.
    */

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

    if((ret = cl_init(CL_INIT_DEFAULT)) != CL_SUCCESS) {
        printf("cl_init() error: %s", cl_strerror(ret));
        return 2;
    }
    if(!(engine = cl_engine_new())) {
        printf("Error, can't create new engine");
        return 2;
    }

    if((ret = cl_load(cl_retdbdir(), engine, &sigs, CL_DB_STDOPT)) != CL_SUCCESS) {
        printf("cl_load() error: %s", cl_strerror(ret));
        close(fd);
        cl_engine_free(engine);
        return 2;
    }

    printf("Loading %u", sigs);

    if((ret = cl_engine_compile(engine)) != CL_SUCCESS) {
        printf("cl_engine_compile error: %s", cl_strerror(ret));
        close(fd);
        cl_engine_free(engine);
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