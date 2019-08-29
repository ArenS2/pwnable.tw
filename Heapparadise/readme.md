# HEAP PARADISE
[heap_paradise](https://github.com/Arens2/pwnable.tw/blob/master/Heapparadise/src/heap_paradise)
[libc](https://github.com/Arens2/pwnable.tw/blob/master/Heapparadise/src/libc_64.so.6)

## Cảm nghĩ: 
   Sau khi làm được tầm 1 nữa số bài trên **pwnable.tw**, bắt đầu từ giờ, những bài hl như thế này sẽ thường xuyên xuất hiện, bước qua 1 level mới (tìm hướng khai thác trong source glibc) nên phải tranh thủ viết writeup thôi. Phải nói là càng làm thì mình càng nói câu "dell tin được" càng nhiều :lol

## Tổng quan:
- Full chế độ bảo vệ nên: tên hàm (`stripped`), địa chỉ code của file ELF (`PIE`), overflow (`canary`), shellcode (`NX`), overwrite .GOT (`RELRO`) quên hết những thèn này đi.
<img src=https://github.com/Arens2/pwnable.tw/blob/master/Heapparadise/src/protected.png>

- Có 2 hàm:
 + Hàm `allocate` thì chỉ cho phép tạo 16 `note`, `size` của mỗi `note` chỉ thuộc `size of fastchunk`, nhập data vào chunk không thể bị overflow. Cũng lạ, bên này cho tạo 16 `note`, thế mà hàm `free` chỉ cho `free` trên 15 thèn thôi. Không biết thèn tác giả có khai thác được chỗ này không chứ fix đi cho đẹp là vừa.
 + Nói chung thông qua hàm này không leak được cái gì, mà còn bị giới hạn `note`, giới hạn `size` của note
<img src=https://github.com/Arens2/pwnable.tw/blob/master/Heapparadise/src/allocate.png>

 + Đến thèn này, hàm `free`, để 1 lỗi kinh điển, free xong dell xóa vùng nhớ, dẫn đến lỗi `double free`, cái này kiểu như có thể phá cả bầu trời rồi.
<img src=https://github.com/Arens2/pwnable.tw/blob/master/Heapparadise/src/free.png>

- Cơ mà nhìn lại có 1 cái hơi khắm, đó là cả chương trình chả leak được bất kì cái địa chỉ gì. Cả chương trình toàn in chuỗi cố định, thà là biến thì mình còn nghĩ cách overwrite để leak gì đấy, đằng này dell leak được qq gì cả. Tới đây thôi là bí cmnr, ngồi khóc 1 bầu trời :TT. Sau 1 ngày tự kỉ với bài này không có hướng, thế là lên google và search, cơ mà đúng khắm thật, tìm thấy mỗi 1 writeup, bằng tiếng Trung thì chẳng nói rồi, nó lại còn viết theo kiểu cho pro xem thì t cũng chịu. Giải thích thì ít, nên ngắm code vậy. Ngắm 1 hồi mới phát hiện ra 1 skill (mặc dù chỉ chiếm `10%` số skill để giải bài này) đó là tuy mình không leak được `addr` nhưng mình lại có `offset` của hàm.
- Đối với `double free`, tuy mình không biết địa chỉ `heap` nhưng mình chỉ cần overwrite `1 byte` là đủ. Kiểu như này:
<img src=https://github.com/Arens2/pwnable.tw/blob/master/Heapparadise/src/double_free.png>

- Thế là có thể tạo 1 `fake chunk` rồi dùng mấy thèn `malloc` chính thống để sửa lại `size` cho nó và thèn `next size` của nó nữa. Sau khi chỉnh `size > 0x80` là nó thuộc `unsorted chunk` rồi, `free` nó 1 phát là có ngay địa chỉ `main_arena+88` trong `heap`. Rồi sau khi đã có gọi là `libc_addr` trong heap rồi cũng chẳng biết làm gì nữa. À rồi từ đâu chợt nghĩ ra thay đổi thèn `fd` của 1 thèn `fastbin` đã `free`, để sau khi `malloc` nó xong, lần `malloc` kế tiếp sẽ rơi vào thèn `fd` của mình. Rồi cơ mà méo biết cái địa chỉ nào thì cho `malloc` đến đâu giờ.
- Đối với bài này mọi chỗ đều bị khóa trừ 3 chỗ có thể khai thác: **malloc_hook**, **free_hook**, **file structure**.
- Với thèn `malloc_hook` và `free_hook`, thà nó có giá trị từ trước thì mình chỉ cần `overwrite 2 byte` là nó sẽ thuộc về thèn `system`, khổ nỗi tụi nó đều bằng `0` mà mình lại không có cái địa chỉ nào. 
- Đối với thèn `file struct`, nếu có `malloc` được đến đó, thì sẽ thay đổi địa chỉ của thèn `vtable` để control toàn bộ hàm trong đó. CƠ mà vẫn câu nói cũ, méo có địa chỉ thì overwrite thèn `vtable` bằng cái gì (`heap` không có), rồi còn mấy cái địa chỉ bên trong lấy đâu ra. Rồi từ đây đọc mãi cái hướng làm pro của thèn `Trung Quốc` kia mà vẫn méo hiểu nó đang nói về kĩ thuật gì, toàn thấy **_IO_2_1_stdout**, lại còn **1/16** mà méo hiểu ... cayyyyyyyyyyyyy

- Thấy nói cứ nhắc mãi đến thèn **_IO_2_1_stdout** bỗng nhớ hồi trước có làm về `file structure` nên lật cái slice của anh **angleboy**. Bắt đầu 1 `kỉ nguyên mới`, `1 thế giới mới` lại bắt đầu từ đây, trong `slide` có nói rất nhiều kĩ thuật mà mình lại hiểu mỗi `10%` của chúng nó, nhưng đoạn gần cuối slice vô tình thấy 1 cách leak địa chỉ tận dụng các hàm in như `puts`, `printf`, ... và không cần quan tâm đến `argument` của chúng. Đây chính là `1 thế giới mới` mà t vừa nhắc đến.

- Vì đó là đoạn gần cuỗi nên cách đó không trình bày rõ ràng, kiểu như phải `set` cái này `set` cái kia, chứ không giải thích tại sao lại như thế, nhưng không sao vì đã nắm được hướng nên tự nghiên cứu cũng được. Sau tầm 1 ngày `debug`, xem `source code glibc`, `testing` các kiểu, cuối cùng t cũng đã biết cách `control` được kĩ thuật đó. Thật kĩ thuật này nó pro đến thế (`60%` skill cho bài này) mà có vẻ chả ăn thua gì so với các `skill` khác trong `slide` của anh **angleboy**, buồn mình vđ. Thôi nói về kĩ thuật đó, kĩ thuật mà t cho là thế giới mới ấy. `Demo` bằng chương trình `Helloworld.c` vậy. `Nof`, m đã thấy vcl chưa, `helloworld` đấy, cách 1 chương trình in ra chữ "Helloworld", à xin phép không thêm `dấu xuống dòng`, cơ mà thật vụ `dấu xuống dòng` lại là cả 1 bầu trời đó. Nhưng không sao bất đầu với hello world nào :x.x
<img src=https://github.com/Arens2/pwnable.tw/blob/master/Heapparadise/src/hworld.png>

- Đấy chương trình đơn giản thôi, 1 dòng `printf` duy nhất thôi. Khi chương trình vào thèn `printf` này, đầu tiên nó chưa biết địa chỉ hàm này đâu, nó phải vào hàm `_dl_runtime_resolve_xsavec()` để gọi hàm `_dl_fixup()`, nhờ thèn này nó mới có được địa chỉ của `__printf()`. Sau đó thèn `__printf()` này sẽ gọi đến thèn `vfprintf_internal()` hàm này hơn thèn `__printf()` ở chỗ nó có thêm tham số là thèn `fd` (_IO_2_1_stdout)
<img src=https://github.com/Arens2/pwnable.tw/blob/master/Heapparadise/src/printf.png>

- Sau đó thèn `vfprintf_internal()` sẽ gọi hàm `_IO_new_file_xsputn()`
<img src=https://github.com/Arens2/pwnable.tw/blob/master/Heapparadise/src/xsputn_start.png>

- Thật ra nó lấy được thèn `_IO_new_file_xsputn()` là nhờ vào thèn **stdout** global variable, chứ không phải từ thèn **_IO_list_all**, sau khi nhờ thèn `stdout`, nó sẽ trả về thèn `_IO_2_1_stdout`, cái mà được truyền lúc nãy vào thèn `vfprintf_internal` ấy, rồi nhờ thèn `_IO_2_1_stdout` nó mới tìm được `vtable`, và nhờ thèn `vtable` mới tìm được thèn `_IO_new_file_xsputn()`
<img src=https://github.com/Arens2/pwnable.tw/blob/master/Heapparadise/src/io_jump_t.png>

- Tới đây khi đã vào được hàm `_IO_new_file_xsputn()`, nó sẽ trải qua hàm `_IO_OVERFLOW()`, chính thèn này là cánh cửa để ta play với `helloworld`.
<img src=https://github.com/Arens2/pwnable.tw/blob/master/Heapparadise/src/xsputn.png>

- Khi nhìn vào hàm `_IO_new_file_overflow()` (thèn này với `_IO_overflow` là 1, đã được `define`) thấy bên dưới có 1 thèn rất vl, đó là thèn `_IO_do_write()`, tham số đầu là `f` (`_io_2_1_stdout`) thì không nói rồi, nhưng tham số 2 mới đặc biệt, nó sẽ in những thèn ở trong địa chỉ được lưu ở thèn `_IO_write_base`, nên nếu ta `overwrite` thèn `_IO_write_base` với 1 địa chỉ khác thì nó sẽ in những gì trong địa chỉ mà ta cung cấp, chính nơi đây là nơi giúp chúng ta `leak` ra được rất nhiều thứ chứ không phải chỉ là chữ `helloworld`.
- Nhưng từ từ, có vài điểm cần lưu ý, thứ #1, tham số thứ 3 của hàm `_IO_do_write()` quyết định `số lượng byte` được in ra = `io_write_ptr` - `io_write_base`.
Thứ #2, để đến được với `_IO_do_write()` chúng ta phải bypass được cái `if` đầu tiên (bằng cách `overwrite` thèn `flag` của `_IO_2_1_stdout` và `clear` `_IO_NO_WRITES` bit), đến thèn `if` thứ 2 cũng thế, chúng ta không nên vào đó làm gì nên phải làm thèn điều kiện của thèn if đó trả về `False`(điều kiện 2 là thèn `_IO_write_base`, cái mà chúng ta đã `overwrite` bởi 1 địa chỉ mà chúng ta muốn nên nó sẽ khác `NULL` rồi, thèn điều kiện đầu chỉ cần set `_IO_CURRENTLY_PUTTING` bit của `_IO_2_1_stdout._flag` nữa là xong)
<img src=https://github.com/Arens2/pwnable.tw/blob/master/Heapparadise/src/overflow.png>
<img src=https://github.com/Arens2/pwnable.tw/blob/master/Heapparadise/src/__flag.png>

- Bây giờ tiếp tục xét xem thèn `_IO_do_write()` sẽ làm gì. Như trong hình, nó sẽ gọi thèn `_IO_SYSWRITE()` để in những thứ trong địa chỉ data của nó với `to_do` `byte` ra màn hình. Nhưng trước khi đến đó nó sẽ qua 1 thèn `if` và `elseif`. Nói về thèn `if` dù vào hay không cũng không ảnh hưởng vì `fp->offset` đã có sắn giá trị là `EOF` rồi, nhưng vì để tránh thèn `elseif` nên ta chỉ cần `set` thêm bit `_IO_IS_APPENDING` nữa là xong.
<img src=https://github.com/Arens2/pwnable.tw/blob/master/Heapparadise/src/write.png>

- Tóm lại đối với bài `helloworld`, ta chỉ cần `set` lại thèn `__flag`, `io_write_base`, và `io_write_ptr` là sẽ ra 1 kết quả khác liền:
<img src=https://github.com/Arens2/pwnable.tw/blob/master/Heapparadise/src/secret_message.png>
<img src=https://github.com/Arens2/pwnable.tw/blob/master/Heapparadise/src/struct_changed.png>

- Và kết quả sẽ là nó sẽ in những gì thuộc địa chỉ mà chúng ta đã `overwrite` thèn `_IO_write_base` của `_IO_2_1_stdout`.
<img src=https://github.com/Arens2/pwnable.tw/blob/master/Heapparadise/src/result.png>

- Đấy kĩ thuật pro mà t muốn nhắc đến là thế đấy, tìm cách thay đổi luồng `flow` trong `source code` thôi. Cơ mà vì mới gặp, biết cách thay đổi luồng thực thi và quan trọng hơn là giải xong bài heaparadise rồi nên t cũng làm biếng quay lại tìm hiểu tại sao `source code` người ta lại viết như thế. Vì `writeup` phải được viết ngay khi làm xong mới nóng nên hẹn dịp khác nghiên cứu về vụ `source code` rồi lại lên đây `edit` tiếp vậy.

- Thôi quay lại bài `HeapParadise` đã: Vậy là ta đã biết cách sử dụng `_IO_2_1_stdout` để `leak` `địa chỉ` rồi, đúng ghê, bài tưởng chừng `không thể` `leak` được bất cứ gì hóa ra giờ lại thế này. Việc tiếp theo là ta sẽ `malloc` đến vùng nhớ của thèn `_IO_2_1_stdout` để `overwrite` 2 thèn `__flag` và `_IO_write_base` thôi. Nhưng có chút vấn đề phát sinh ở đây: chúng ta không biết địa chỉ của thèn `_IO_2_1_stdout` làm sao mà `malloc` đến, lại 1 lần nữa, chúng ta sử dụng `offset`, để ý `addr` of thèn `main_arena+88` và thèn `_IO_2_1_stdout` chỉ `khác nhau` `16bit`, cơ mà `libc_base` lại có `12bit` cuối bằng `0` đến ta chỉ việc `bruteforce` `4 bit` còn lại để có thể vào được vùng nhớ của `_IO_2_1_stdout`, cơ hội là `1/16` thôi, hehe.
<img src=https://github.com/Arens2/pwnable.tw/blob/master/Heapparadise/src/2byte.png>

- À xém quên, `overwrite` thèn `__flag` thì dễ rồi, còn thèn `_IO_write_base`, nếu chúng ta `overwrite` thèn đó chỉ với `1 byte` thì số lượng byte sau khi trừ sẽ `< 0` và `không leak được gì`, nên ta phải `overwrite 2 byte` để nó lên trên thèn `_IO_2_1_stdout` luôn, như lần trước thoạt đầu cứ nghĩ ta sẽ phải tiếp tục `bruteforce 4bit nữa `nhưng thực tế là không cần, lần trước ta đã `bruteforce` rồi, và nếu thành công thì `4bit` đó sẽ rơi ngay vào vùng nhớ của `_IO_2_1_stderr` nên ta chỉ cần sử dụng lại `byte` đó là được. Đến đó là đã xong vụ địa chỉ rồi.
<img src=https://github.com/Arens2/pwnable.tw/blob/master/Heapparadise/src/todo_byte.png>
<img src=https://github.com/Arens2/pwnable.tw/blob/master/Heapparadise/src/setup.png>
<img src=https://github.com/Arens2/pwnable.tw/blob/master/Heapparadise/src/table.png>
<img src=https://github.com/Arens2/pwnable.tw/blob/master/Heapparadise/src/leak_addr.png>

- Sau khi đã có `libc_base`-> `system`, chúng ta có 3 nơi để `overwrite`. Nơi 1 là **malloc_hook**, nếu chúng ta overwirte vào thèn này thì khi gọi `malloc()` sẽ gọi `system()`, nhưng `tham số` của `system` phải là `địa chỉ của /bin/sh` mà địa chỉ thì nó sẽ luôn `> 0x78` (giới hạn về `size` khi `malloc` ở hàm `allocate`), tiếp đến là `overwrite` **free_hook()**, thèn này nói chung nếu `overwrite` được sẽ rất tuyệt vời vì `free` 1 địa chỉ mà mình có thể ghi `/bin/sh` vào đó, quá tiện còn gì , nhưng mà để làm được thì ta phải dùng `unsorted bin attack` vì xung quanh thèn `free_hook()` chỉ toàn là `NULL byte`, nếu thế thì sẽ làm tăng số lượng `malloc()` quá `16` lần, dẫn đến không được luôn. Cách nữa là `overwrite` thèn **vtable** để bên trong toàn là `system` nhưng lại có 2 nhược điểm: #1 `vtable` sẽ phải mang giá trị của vùng nhớ `heap` mà ta lại chưa thể `leak` được `heap addr`, thứ 2, nếu `overwrite` các hàm bên trong `vtable` thì ta chỉ có thể sử dụng `one_gadget` chứ không thể là `system` được. Cơ mà vì lí do 1 `fail` nên cách này cũng không được nốt luôn. Thế là 3 phương án: `malloc_hook`, `free_hook`, `vtable` đều không xong. Nhưng nhìn kĩ lại thèn `malloc_hook` lại là thèn triển vọng nhất lúc này vì tuy nó không thể sử dụng tham số nhưng nó có thể là `one_gadget`, test thử và pinggo. Vừa đủ số `malloc` là `16`, lại có 2 thèn `one_gadget` thỏa mãn. Cuối cùng cũng xong, bài này vã vl, mất 1 tuần hôm nay là `deadline` cho bài này mà giờ `00h02p` rồi, chỗ tự học kí túc xá `1 mình` nữa, haizzz. Thôi cố gắng thêm tí nữa, push lên git rồi đi ngủ :haha

<img src=https://github.com/Arens2/pwnable.tw/blob/master/Heapparadise/src/flag.png>

[Heap_paradise.py](https://github.com/Arens2/pwnable.tw/blob/master/Heapparadise/exp.py)

## Reference
[Play with file structure](https://gsec.hitb.org/materials/sg2018/WHITEPAPERS/FILE%20Structures%20-%20Another%20Binary%20Exploitation%20Technique%20-%20An-Jie%20Yang.pdf)
[Source code glibc](https://code.woboq.org/userspace/glibc/)

