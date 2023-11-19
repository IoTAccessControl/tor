
### c hashmap lib  

https://github.com/tidwall/hashmap.c/tree/master  
开地址多次hash。

TODO: 对项目提pull request，提交对hashmap的修改。

接口改造成ebpf的形式
```
#include <linux/bpf.h>

union bpf_attr my_map_attr {
  .map_type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(int),
  .value_size = sizeof(int),
  .max_entries = 1024,
};

int fd = bpf(BPF_MAP_CREATE, &my_map_attr, sizeof(my_map_attr));
```