import cpp


from Macro m
//where m.getName() = "ntohs" or m.getName() = "ntohl" or m.getName() = "ntohll"
where m.getName().regexpMatch("ntoh(s|l|ll)")
select m, "a macro to find ntohs, ntohl, and ntohll"
