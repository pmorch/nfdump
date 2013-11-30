int scandir(const char *dir, struct dirent ***namelist,
            const int (*select)(const struct dirent *),
            const int (*compar)(const void *, const void *));

int alphasort(const void *a, const void *b);
