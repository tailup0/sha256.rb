#!/usr/bin/env ruby
class Sha256
  # 定数K
  # サイズ: 32bit(4Byte) x 8 = 256bit
  INT_K = ['428a2f98', '71374491', 'b5c0fbcf', 'e9b5dba5', '3956c25b', '59f111f1', '923f82a4', 'ab1c5ed5',
           'd807aa98', '12835b01', '243185be', '550c7dc3', '72be5d74', '80deb1fe', '9bdc06a7', 'c19bf174',
           'e49b69c1', 'efbe4786', '0fc19dc6', '240ca1cc', '2de92c6f', '4a7484aa', '5cb0a9dc', '76f988da',
           '983e5152', 'a831c66d', 'b00327c8', 'bf597fc7', 'c6e00bf3', 'd5a79147', '06ca6351', '14292967',
           '27b70a85', '2e1b2138', '4d2c6dfc', '53380d13', '650a7354', '766a0abb', '81c2c92e', '92722c85',
           'a2bfe8a1', 'a81a664b', 'c24b8b70', 'c76c51a3', 'd192e819', 'd6990624', 'f40e3585', '106aa070',
           '19a4c116', '1e376c08', '2748774c', '34b0bcb5', '391c0cb3', '4ed8aa4a', '5b9cca4f', '682e6ff3',
           '748f82ee', '78a5636f', '84c87814', '8cc70208', '90befffa', 'a4506ceb', 'bef9a3f7', 'c67178f2']

  # ハッシュの初期値
  # サイズ: 32bit(4Byte) x 8 = 256bit
  INITIAL_HATH = ['6a09e667', 'bb67ae85', '3c6ef372', 'a54ff53a',
                  '510e527f', '9b05688c', '1f83d9ab', '5be0cd19']

  # １ワードあたりのビット数
  W = 32

  # Helper
  # 右ビットシフト(SHift Right)
  def SHR(v, n)
    v >> n
  end
  # 左ビットシフト(SHift Left)
  def SHL(v, n)
    v << n
  end
  # 右ビット回転(ROTate Right)
  def ROTR(v, n)
    ("%0#{W}b" % v).split("").rotate(-n).join.to_i(2)
  end
  # 左ビット回転(ROTate Left)
  def ROTL(v, n)
    ("%0#{W}b" % v).split("").rotate(n).join.to_i(2)
  end
  # 引数をすべて加算し、32bit以上の桁については破棄する
  def ShaAdd(*v)
    v.inject(:+) & 0xFFFFFFFF
  end
  def Int32Str(v)
    ("%08x" % v)[-8,8]
  end
  # 文字列を指定文字数ずつ配列にする
  def S2Ar(s, n)
    s.scan(/.{1,#{n}}/)
  end
  def ArrayEach64byte(bytes)
    i = 0
    resAr = []
    ar = []
    bytes.each{|byte|
      i += 1
      ar.push(byte)
      if i % 64 == 0
        resAr.push(ar)
        ar = []
      end
    }
    resAr
  end

  # ハッシュ計算用関数
  # Ch
  def Ch(x, y, z)
    (x & y) ^ (~x & z)
  end
  # Maj
  def Maj(x, y, z)
    (x & y) ^ (x & z) ^ (y & z)
  end
  # シグマA0(Σ0)
  def SigmaA0(x)
    ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22)
  end
  # シグマA1(Σ1)
  def SigmaA1(x)
    ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25)
  end
  # シグマB0(σ0)
  def SigmaB0(x)
    ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3)
  end
  # シグマB1(σ1)
  def SigmaB1(x)
    ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10)
  end

  # 与えられたブロックのローテーション処理を行う
  def Computation(hash, block)
    intW = Array.new(64) # blockから生成される64Byteの配列

    # 現在のハッシュを複製
    intA = hash[0].to_i(16)
    intB = hash[1].to_i(16)
    intC = hash[2].to_i(16)
    intD = hash[3].to_i(16)
    intE = hash[4].to_i(16)
    intF = hash[5].to_i(16)
    intG = hash[6].to_i(16)
    intH = hash[7].to_i(16)

    # ローテーション処理
    # 定数KやintW(Blockの配列)、現在のハッシュ値などを用いて64回、
    # ハッシュ値をローテーションさせる
    # intWの配列は回転させながら作る
    0.upto(63){|i|
      if i < 16
      # 0-15は、Blockの配列を4byteずつ代入していく
        ar = []
        ar.push(block[4 * i])
        ar.push(block[1 + 4 * i])
        ar.push(block[2 + 4 * i])
        ar.push(block[3 + 4 * i])
        intW[i] = ar.join.to_i(16)
      else
      # 16-63は、すでに代入された値から生成する
        intW[i] = ShaAdd(SigmaB1(intW[i - 2]), intW[i - 7],
                         SigmaB0(intW[i - 15]), intW[i - 16])
      end

      # ローテーション時に変化を与える値を算出
      t1 = ShaAdd(intH, SigmaA1(intE), Ch(intE, intF, intG), INT_K[i].to_i(16), intW[i])
      t2 = ShaAdd(SigmaA0(intA), Maj(intA, intB, intC))

      # ハッシュ値ローテーション
      # (intEとintAで変化を与える。ここで失われるintHはt1の計算に使われている)
      intH = intG
      intG = intF
      intF = intE
      intE = ShaAdd(intD, t1)
      intD = intC
      intC = intB
      intB = intA
      intA = ShaAdd(t1, t2)
    }

    # 算出されたハッシュを現在のハッシュに加算
    resHash = Array.new(8)
    resHash[0] = Int32Str(ShaAdd(hash[0].to_i(16), intA))
    resHash[1] = Int32Str(ShaAdd(hash[1].to_i(16), intB))
    resHash[2] = Int32Str(ShaAdd(hash[2].to_i(16), intC))
    resHash[3] = Int32Str(ShaAdd(hash[3].to_i(16), intD))
    resHash[4] = Int32Str(ShaAdd(hash[4].to_i(16), intE))
    resHash[5] = Int32Str(ShaAdd(hash[5].to_i(16), intF))
    resHash[6] = Int32Str(ShaAdd(hash[6].to_i(16), intG))
    resHash[7] = Int32Str(ShaAdd(hash[7].to_i(16), intH))
    resHash
  end

  def Padding(bytes)
    bytes = S2Ar(bytes, 2)

    # 元のデータのバイト数
    orgByteLength = bytes.length
    # 元のデータのビット数
    orgBitLength = orgByteLength * 8
    # 元のデータのビット数の16進数文字列
    orgBitLengthString = orgBitLength.to_s(16)
    # 数値を16進数文字列にする際、文字列の長さを調整する為0埋め
    if orgBitLengthString.length.odd?
      orgBitLengthString = '0' + orgBitLengthString
    end
    # 元のデータのビット数の16進数文字列自体のバイト数
    orgBitLengthStringByteLength = S2Ar(orgBitLengthString, 2).length

    ## 元のデータ末尾にbitを立てる
    bytes.push('80')
    # 最後のブロックが56バイトを超える場合は、ブロックの総数を１つ増やす
    if bytes.length % 64 > 56
      blockCount = bytes.length / 64 + 2
    else
      blockCount = bytes.length / 64 + 1
    end
    # 00埋めする個数
    padLength = blockCount * 64 - bytes.length - orgBitLengthStringByteLength
    padLength.times{
      bytes.push('00')
    }
    S2Ar(bytes.join + orgBitLengthString, 2)
  end

  # SHA-256アルゴリズムによりメッセージダイジェスト(64byte)を取得します。
  def Hash(bytes)
    # パディング
    # ブロック長(64byte)の倍数になるようにデータ長を調整
    bytes = Padding(bytes)

    # ブロックに分けてハッシュ値を計算
    # 64byteごとに分けてループ
    intHash = INITIAL_HATH
    bytesEach64 = ArrayEach64byte(bytes)
    bytesEach64.each{|bytes|
      intHash = Computation(intHash, bytes)
    }
    intHash.join
  end

end

sha256 = Sha256.new
v = ARGV[0]
puts sha256.Hash(v.unpack('H*').first)
