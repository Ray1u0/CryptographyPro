# edit distance/Hamming distance

The [Hamming distance][1] is just the number of differing bits.

[1]:http://cryptopals.com/sets/1/challenges/6

两个等长字符串中不同的比特数，一种简单的实现方法是：
将两字符串异或，求结果中“1”的个数。
<https://trustedsignal.blogspot.com/2015/06/xord-play-normalized-hamming-distance.html>
