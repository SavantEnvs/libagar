FROM ubuntu:22.04 AS builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential libfreetype6-dev clang

COPY . /repo
WORKDIR /repo
RUN ./configure --without-freetype --prefix=/install
RUN make -j8
RUN make install

RUN ./configure --without-freetype
RUN make -j8
RUN make install

WORKDIR /repo/tools/agar-disasm
RUN ./configure --prefix=/install
RUN make
RUN make install
ENV LD_LIBRARY_PATH=/repo/core
RUN clang++ /repo/mayhem/fuzz_ag_length_utf8.cpp -fsanitize=fuzzer,address -I /install/include/agar/agar/ -I /install/include/agar/ -o /fuzz

FROM ubuntu:22.04 AS package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libpng-dev
COPY --from=builder /install /install
COPY --from=builder /fuzz /fuzz_ag_length_utf8
ENV LD_LIBRARY_PATH=/install/lib
