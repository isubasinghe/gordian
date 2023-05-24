(set-logic QF_ABV)
(set-option :produce-models true)

(define-sort PD () (_ BitVec 6))
(define-sort PD<> () (_ BitVec 6))
(define-fun <PD00> () PD<> (_ bv0 6))
(define-fun <PD01> () PD<> (_ bv1 6))
(define-fun <PD02> () PD<> (_ bv2 6))
(define-fun <PD03> () PD<> (_ bv3 6))
(define-fun <PD04> () PD<> (_ bv4 6))
(define-fun <PD05> () PD<> (_ bv5 6))
(define-fun <PD06> () PD<> (_ bv6 6))
(define-fun <PD07> () PD<> (_ bv7 6))
(define-fun <PD08> () PD<> (_ bv8 6))
(define-fun <PD09> () PD<> (_ bv9 6))
(define-fun <PD10> () PD<> (_ bv10 6))
(define-fun <PD11> () PD<> (_ bv11 6))
(define-fun <PD12> () PD<> (_ bv12 6))
(define-fun <PD13> () PD<> (_ bv13 6))
(define-fun <PD14> () PD<> (_ bv14 6))
(define-fun <PD15> () PD<> (_ bv15 6))
(define-fun <PD16> () PD<> (_ bv16 6))
(define-fun <PD17> () PD<> (_ bv17 6))
(define-fun <PD18> () PD<> (_ bv18 6))
(define-fun <PD19> () PD<> (_ bv19 6))
(define-fun <PD20> () PD<> (_ bv20 6))
(define-fun <PD21> () PD<> (_ bv21 6))
(define-fun <PD22> () PD<> (_ bv22 6))
(define-fun <PD23> () PD<> (_ bv23 6))
(define-fun <PD24> () PD<> (_ bv24 6))
(define-fun <PD25> () PD<> (_ bv25 6))
(define-fun <PD26> () PD<> (_ bv26 6))
(define-fun <PD27> () PD<> (_ bv27 6))
(define-fun <PD28> () PD<> (_ bv28 6))
(define-fun <PD29> () PD<> (_ bv29 6))
(define-fun <PD30> () PD<> (_ bv30 6))
(define-fun <PD31> () PD<> (_ bv31 6))
(define-fun <PD32> () PD<> (_ bv32 6))
(define-fun <PD33> () PD<> (_ bv33 6))
(define-fun <PD34> () PD<> (_ bv34 6))
(define-fun <PD35> () PD<> (_ bv35 6))
(define-fun <PD36> () PD<> (_ bv36 6))
(define-fun <PD37> () PD<> (_ bv37 6))
(define-fun <PD38> () PD<> (_ bv38 6))
(define-fun <PD39> () PD<> (_ bv39 6))
(define-fun <PD40> () PD<> (_ bv40 6))
(define-fun <PD41> () PD<> (_ bv41 6))
(define-fun <PD42> () PD<> (_ bv42 6))
(define-fun <PD43> () PD<> (_ bv43 6))
(define-fun <PD44> () PD<> (_ bv44 6))
(define-fun <PD45> () PD<> (_ bv45 6))
(define-fun <PD46> () PD<> (_ bv46 6))
(define-fun <PD47> () PD<> (_ bv47 6))
(define-fun <PD48> () PD<> (_ bv48 6))
(define-fun <PD49> () PD<> (_ bv49 6))
(define-fun <PD50> () PD<> (_ bv50 6))
(define-fun <PD51> () PD<> (_ bv51 6))
(define-fun <PD52> () PD<> (_ bv52 6))
(define-fun <PD53> () PD<> (_ bv53 6))
(define-fun <PD54> () PD<> (_ bv54 6))
(define-fun <PD55> () PD<> (_ bv55 6))
(define-fun <PD56> () PD<> (_ bv56 6))
(define-fun <PD57> () PD<> (_ bv57 6))
(define-fun <PD58> () PD<> (_ bv58 6))
(define-fun <PD59> () PD<> (_ bv59 6))
(define-fun <PD60> () PD<> (_ bv60 6))
(define-fun <PD61> () PD<> (_ bv61 6))
(define-fun <PD62> () PD<> (_ bv62 6))
(assert (distinct <PD00> <PD01> <PD02> <PD03> <PD04> <PD05> <PD06> <PD07> <PD08> <PD09> <PD10> <PD11> <PD12> <PD13> <PD14> <PD15> <PD16> <PD17> <PD18> <PD19> <PD20> <PD21> <PD22> <PD23> <PD24> <PD25> <PD26> <PD27> <PD28> <PD29> <PD30> <PD31> <PD32> <PD33> <PD34> <PD35> <PD36> <PD37> <PD38> <PD39> <PD40> <PD41> <PD42> <PD43> <PD44> <PD45> <PD46> <PD47> <PD48> <PD49> <PD50> <PD51> <PD52> <PD53> <PD54> <PD55> <PD56> <PD57> <PD58> <PD59> <PD60> <PD61> <PD62>))
(define-fun PD.<> ((v PD)) PD<> ((_ extract 5 0) v))
(define-fun PD00 () PD <PD00>)
(define-fun PD01 () PD <PD01>)
(define-fun PD02 () PD <PD02>)
(define-fun PD03 () PD <PD03>)
(define-fun PD04 () PD <PD04>)
(define-fun PD05 () PD <PD05>)
(define-fun PD06 () PD <PD06>)
(define-fun PD07 () PD <PD07>)
(define-fun PD08 () PD <PD08>)
(define-fun PD09 () PD <PD09>)
(define-fun PD10 () PD <PD10>)
(define-fun PD11 () PD <PD11>)
(define-fun PD12 () PD <PD12>)
(define-fun PD13 () PD <PD13>)
(define-fun PD14 () PD <PD14>)
(define-fun PD15 () PD <PD15>)
(define-fun PD16 () PD <PD16>)
(define-fun PD17 () PD <PD17>)
(define-fun PD18 () PD <PD18>)
(define-fun PD19 () PD <PD19>)
(define-fun PD20 () PD <PD20>)
(define-fun PD21 () PD <PD21>)
(define-fun PD22 () PD <PD22>)
(define-fun PD23 () PD <PD23>)
(define-fun PD24 () PD <PD24>)
(define-fun PD25 () PD <PD25>)
(define-fun PD26 () PD <PD26>)
(define-fun PD27 () PD <PD27>)
(define-fun PD28 () PD <PD28>)
(define-fun PD29 () PD <PD29>)
(define-fun PD30 () PD <PD30>)
(define-fun PD31 () PD <PD31>)
(define-fun PD32 () PD <PD32>)
(define-fun PD33 () PD <PD33>)
(define-fun PD34 () PD <PD34>)
(define-fun PD35 () PD <PD35>)
(define-fun PD36 () PD <PD36>)
(define-fun PD37 () PD <PD37>)
(define-fun PD38 () PD <PD38>)
(define-fun PD39 () PD <PD39>)
(define-fun PD40 () PD <PD40>)
(define-fun PD41 () PD <PD41>)
(define-fun PD42 () PD <PD42>)
(define-fun PD43 () PD <PD43>)
(define-fun PD44 () PD <PD44>)
(define-fun PD45 () PD <PD45>)
(define-fun PD46 () PD <PD46>)
(define-fun PD47 () PD <PD47>)
(define-fun PD48 () PD <PD48>)
(define-fun PD49 () PD <PD49>)
(define-fun PD50 () PD <PD50>)
(define-fun PD51 () PD <PD51>)
(define-fun PD52 () PD <PD52>)
(define-fun PD53 () PD <PD53>)
(define-fun PD54 () PD <PD54>)
(define-fun PD55 () PD <PD55>)
(define-fun PD56 () PD <PD56>)
(define-fun PD57 () PD <PD57>)
(define-fun PD58 () PD <PD58>)
(define-fun PD59 () PD <PD59>)
(define-fun PD60 () PD <PD60>)
(define-fun PD61 () PD <PD61>)
(define-fun PD62 () PD <PD62>)

(define-sort Ch () (_ BitVec 6))
(define-sort Ch<> () (_ BitVec 6))
(define-fun <Ch00> () Ch<> (_ bv0 6))
(define-fun <Ch01> () Ch<> (_ bv1 6))
(define-fun <Ch02> () Ch<> (_ bv2 6))
(define-fun <Ch03> () Ch<> (_ bv3 6))
(define-fun <Ch04> () Ch<> (_ bv4 6))
(define-fun <Ch05> () Ch<> (_ bv5 6))
(define-fun <Ch06> () Ch<> (_ bv6 6))
(define-fun <Ch07> () Ch<> (_ bv7 6))
(define-fun <Ch08> () Ch<> (_ bv8 6))
(define-fun <Ch09> () Ch<> (_ bv9 6))
(define-fun <Ch10> () Ch<> (_ bv10 6))
(define-fun <Ch11> () Ch<> (_ bv11 6))
(define-fun <Ch12> () Ch<> (_ bv12 6))
(define-fun <Ch13> () Ch<> (_ bv13 6))
(define-fun <Ch14> () Ch<> (_ bv14 6))
(define-fun <Ch15> () Ch<> (_ bv15 6))
(define-fun <Ch16> () Ch<> (_ bv16 6))
(define-fun <Ch17> () Ch<> (_ bv17 6))
(define-fun <Ch18> () Ch<> (_ bv18 6))
(define-fun <Ch19> () Ch<> (_ bv19 6))
(define-fun <Ch20> () Ch<> (_ bv20 6))
(define-fun <Ch21> () Ch<> (_ bv21 6))
(define-fun <Ch22> () Ch<> (_ bv22 6))
(define-fun <Ch23> () Ch<> (_ bv23 6))
(define-fun <Ch24> () Ch<> (_ bv24 6))
(define-fun <Ch25> () Ch<> (_ bv25 6))
(define-fun <Ch26> () Ch<> (_ bv26 6))
(define-fun <Ch27> () Ch<> (_ bv27 6))
(define-fun <Ch28> () Ch<> (_ bv28 6))
(define-fun <Ch29> () Ch<> (_ bv29 6))
(define-fun <Ch30> () Ch<> (_ bv30 6))
(define-fun <Ch31> () Ch<> (_ bv31 6))
(define-fun <Ch32> () Ch<> (_ bv32 6))
(define-fun <Ch33> () Ch<> (_ bv33 6))
(define-fun <Ch34> () Ch<> (_ bv34 6))
(define-fun <Ch35> () Ch<> (_ bv35 6))
(define-fun <Ch36> () Ch<> (_ bv36 6))
(define-fun <Ch37> () Ch<> (_ bv37 6))
(define-fun <Ch38> () Ch<> (_ bv38 6))
(define-fun <Ch39> () Ch<> (_ bv39 6))
(define-fun <Ch40> () Ch<> (_ bv40 6))
(define-fun <Ch41> () Ch<> (_ bv41 6))
(define-fun <Ch42> () Ch<> (_ bv42 6))
(define-fun <Ch43> () Ch<> (_ bv43 6))
(define-fun <Ch44> () Ch<> (_ bv44 6))
(define-fun <Ch45> () Ch<> (_ bv45 6))
(define-fun <Ch46> () Ch<> (_ bv46 6))
(define-fun <Ch47> () Ch<> (_ bv47 6))
(define-fun <Ch48> () Ch<> (_ bv48 6))
(define-fun <Ch49> () Ch<> (_ bv49 6))
(define-fun <Ch50> () Ch<> (_ bv50 6))
(define-fun <Ch51> () Ch<> (_ bv51 6))
(define-fun <Ch52> () Ch<> (_ bv52 6))
(define-fun <Ch53> () Ch<> (_ bv53 6))
(define-fun <Ch54> () Ch<> (_ bv54 6))
(define-fun <Ch55> () Ch<> (_ bv55 6))
(define-fun <Ch56> () Ch<> (_ bv56 6))
(define-fun <Ch57> () Ch<> (_ bv57 6))
(define-fun <Ch58> () Ch<> (_ bv58 6))
(define-fun <Ch59> () Ch<> (_ bv59 6))
(define-fun <Ch60> () Ch<> (_ bv60 6))
(define-fun <Ch61> () Ch<> (_ bv61 6))
(define-fun <Ch62> () Ch<> (_ bv62 6))
(assert (distinct <Ch00> <Ch01> <Ch02> <Ch03> <Ch04> <Ch05> <Ch06> <Ch07> <Ch08> <Ch09> <Ch10> <Ch11> <Ch12> <Ch13> <Ch14> <Ch15> <Ch16> <Ch17> <Ch18> <Ch19> <Ch20> <Ch21> <Ch22> <Ch23> <Ch24> <Ch25> <Ch26> <Ch27> <Ch28> <Ch29> <Ch30> <Ch31> <Ch32> <Ch33> <Ch34> <Ch35> <Ch36> <Ch37> <Ch38> <Ch39> <Ch40> <Ch41> <Ch42> <Ch43> <Ch44> <Ch45> <Ch46> <Ch47> <Ch48> <Ch49> <Ch50> <Ch51> <Ch52> <Ch53> <Ch54> <Ch55> <Ch56> <Ch57> <Ch58> <Ch59> <Ch60> <Ch61> <Ch62>))
(define-fun Ch.<> ((v Ch)) Ch<> ((_ extract 5 0) v))
(define-fun Ch00 () Ch <Ch00>)
(define-fun Ch01 () Ch <Ch01>)
(define-fun Ch02 () Ch <Ch02>)
(define-fun Ch03 () Ch <Ch03>)
(define-fun Ch04 () Ch <Ch04>)
(define-fun Ch05 () Ch <Ch05>)
(define-fun Ch06 () Ch <Ch06>)
(define-fun Ch07 () Ch <Ch07>)
(define-fun Ch08 () Ch <Ch08>)
(define-fun Ch09 () Ch <Ch09>)
(define-fun Ch10 () Ch <Ch10>)
(define-fun Ch11 () Ch <Ch11>)
(define-fun Ch12 () Ch <Ch12>)
(define-fun Ch13 () Ch <Ch13>)
(define-fun Ch14 () Ch <Ch14>)
(define-fun Ch15 () Ch <Ch15>)
(define-fun Ch16 () Ch <Ch16>)
(define-fun Ch17 () Ch <Ch17>)
(define-fun Ch18 () Ch <Ch18>)
(define-fun Ch19 () Ch <Ch19>)
(define-fun Ch20 () Ch <Ch20>)
(define-fun Ch21 () Ch <Ch21>)
(define-fun Ch22 () Ch <Ch22>)
(define-fun Ch23 () Ch <Ch23>)
(define-fun Ch24 () Ch <Ch24>)
(define-fun Ch25 () Ch <Ch25>)
(define-fun Ch26 () Ch <Ch26>)
(define-fun Ch27 () Ch <Ch27>)
(define-fun Ch28 () Ch <Ch28>)
(define-fun Ch29 () Ch <Ch29>)
(define-fun Ch30 () Ch <Ch30>)
(define-fun Ch31 () Ch <Ch31>)
(define-fun Ch32 () Ch <Ch32>)
(define-fun Ch33 () Ch <Ch33>)
(define-fun Ch34 () Ch <Ch34>)
(define-fun Ch35 () Ch <Ch35>)
(define-fun Ch36 () Ch <Ch36>)
(define-fun Ch37 () Ch <Ch37>)
(define-fun Ch38 () Ch <Ch38>)
(define-fun Ch39 () Ch <Ch39>)
(define-fun Ch40 () Ch <Ch40>)
(define-fun Ch41 () Ch <Ch41>)
(define-fun Ch42 () Ch <Ch42>)
(define-fun Ch43 () Ch <Ch43>)
(define-fun Ch44 () Ch <Ch44>)
(define-fun Ch45 () Ch <Ch45>)
(define-fun Ch46 () Ch <Ch46>)
(define-fun Ch47 () Ch <Ch47>)
(define-fun Ch48 () Ch <Ch48>)
(define-fun Ch49 () Ch <Ch49>)
(define-fun Ch50 () Ch <Ch50>)
(define-fun Ch51 () Ch <Ch51>)
(define-fun Ch52 () Ch <Ch52>)
(define-fun Ch53 () Ch <Ch53>)
(define-fun Ch54 () Ch <Ch54>)
(define-fun Ch55 () Ch <Ch55>)
(define-fun Ch56 () Ch <Ch56>)
(define-fun Ch57 () Ch <Ch57>)
(define-fun Ch58 () Ch <Ch58>)
(define-fun Ch59 () Ch <Ch59>)
(define-fun Ch60 () Ch <Ch60>)
(define-fun Ch61 () Ch <Ch61>)
(define-fun Ch62 () Ch <Ch62>)

(define-sort MsgInfo_Label () (_ BitVec 52))
(define-sort MsgInfo_Count () (_ BitVec 12))

; Set Ch
(define-sort Ch_set () (_ BitVec 64))
(define-fun Ch_set_empty () Ch_set (_ bv0 64))
(define-fun Ch_set_singleton ((x Ch)) Ch_set (bvshl (_ bv1 64) ((_ zero_extend 58) x)))
(define-fun Ch_set_intersection ((s1 Ch_set) (s2 Ch_set)) Ch_set (bvand s1 s2))
(define-fun Ch_set_union ((s1 Ch_set) (s2 Ch_set)) Ch_set (bvor s1 s2))
(define-fun Ch_set_has ((s Ch_set) (x Ch)) Bool (bvult (_ bv0 64) (bvand s (Ch_set_singleton x))))
(define-fun Ch_set_add ((s Ch_set) (x Ch)) Ch_set (Ch_set_union s (Ch_set_singleton x)))
(define-fun Ch_set_remove ((s Ch_set) (x Ch)) Ch_set (Ch_set_intersection s (Ch_set_singleton x)))

; data MsgInfo = MI
;   { label :: MsgInfo_Label
;   , count :: MsgInfo_Count
;   }
(define-sort MsgInfo () (_ BitVec 64))
(define-fun MI ((a MsgInfo_Label) (b MsgInfo_Count)) MsgInfo (concat a b))
(define-fun label ((c MsgInfo)) MsgInfo_Label ((_ extract 63 12) c))
(define-fun label= ((c MsgInfo) (v MsgInfo_Label)) MsgInfo (concat v ((_ extract 11 0) c)))
(define-fun count ((c MsgInfo)) MsgInfo_Count ((_ extract 11 0) c))
(define-fun count= ((c MsgInfo) (v MsgInfo_Count)) MsgInfo (concat ((_ extract 63 12) c) v))

; type Prod_Ch_MsgInfo = (Ch, MsgInfo)
(define-sort Prod_Ch_MsgInfo () (_ BitVec 70))
(define-fun Prod_Ch_MsgInfo ((fst Ch) (snd MsgInfo)) Prod_Ch_MsgInfo (concat fst snd))
(define-fun Prod_Ch_MsgInfo.fst ((p Prod_Ch_MsgInfo)) Ch ((_ extract 69 64) p))
(define-fun Prod_Ch_MsgInfo.snd ((p Prod_Ch_MsgInfo)) MsgInfo ((_ extract 63 0) p))
(define-fun Prod_Ch_MsgInfo.fst= ((p Prod_Ch_MsgInfo) (x Ch)) Prod_Ch_MsgInfo (concat x (Prod_Ch_MsgInfo.snd p)))
(define-fun Prod_Ch_MsgInfo.snd= ((p Prod_Ch_MsgInfo) (x MsgInfo)) Prod_Ch_MsgInfo (concat (Prod_Ch_MsgInfo.fst p) x))

(define-sort SeL4_Ntfn () (_ BitVec 64))
; type Prod_MsgInfo_SeL4_Ntfn = (MsgInfo, SeL4_Ntfn)
(define-sort Prod_MsgInfo_SeL4_Ntfn () (_ BitVec 128))
(define-fun Prod_MsgInfo_SeL4_Ntfn ((fst MsgInfo) (snd SeL4_Ntfn)) Prod_MsgInfo_SeL4_Ntfn (concat fst snd))
(define-fun Prod_MsgInfo_SeL4_Ntfn.fst ((p Prod_MsgInfo_SeL4_Ntfn)) MsgInfo ((_ extract 127 64) p))
(define-fun Prod_MsgInfo_SeL4_Ntfn.snd ((p Prod_MsgInfo_SeL4_Ntfn)) SeL4_Ntfn ((_ extract 63 0) p))
(define-fun Prod_MsgInfo_SeL4_Ntfn.fst= ((p Prod_MsgInfo_SeL4_Ntfn) (x MsgInfo)) Prod_MsgInfo_SeL4_Ntfn (concat x (Prod_MsgInfo_SeL4_Ntfn.snd p)))
(define-fun Prod_MsgInfo_SeL4_Ntfn.snd= ((p Prod_MsgInfo_SeL4_Ntfn) (x SeL4_Ntfn)) Prod_MsgInfo_SeL4_Ntfn (concat (Prod_MsgInfo_SeL4_Ntfn.fst p) x))

(define-sort Maybe_Prod_MsgInfo_SeL4_Ntfn () (_ BitVec 129))
(define-sort Maybe_Prod_MsgInfo_SeL4_Ntfn<> () (_ BitVec 1))
(declare-fun <Prod_MsgInfo_SeL4_Ntfn_Nothing> () Maybe_Prod_MsgInfo_SeL4_Ntfn<>)
(declare-fun <Prod_MsgInfo_SeL4_Ntfn_Just> () Maybe_Prod_MsgInfo_SeL4_Ntfn<>)
(assert (distinct <Prod_MsgInfo_SeL4_Ntfn_Nothing> <Prod_MsgInfo_SeL4_Ntfn_Just>))
(define-fun Maybe_Prod_MsgInfo_SeL4_Ntfn.<> ((v Maybe_Prod_MsgInfo_SeL4_Ntfn)) Maybe_Prod_MsgInfo_SeL4_Ntfn<> ((_ extract 128 128) v))
(define-fun Prod_MsgInfo_SeL4_Ntfn_Nothing () Maybe_Prod_MsgInfo_SeL4_Ntfn (concat <Prod_MsgInfo_SeL4_Ntfn_Nothing> (_ bv0 128)))
(define-fun Prod_MsgInfo_SeL4_Ntfn_Just.1 ((v Maybe_Prod_MsgInfo_SeL4_Ntfn)) Prod_MsgInfo_SeL4_Ntfn ((_ extract 127 0) v))
(define-fun Prod_MsgInfo_SeL4_Ntfn_Just ((a Prod_MsgInfo_SeL4_Ntfn)) Maybe_Prod_MsgInfo_SeL4_Ntfn (concat <Prod_MsgInfo_SeL4_Ntfn_Just> a))

(define-sort NextRecv () (_ BitVec 72))
(define-sort NextRecv<> () (_ BitVec 2))
(declare-fun <NR_Notification> () NextRecv<>)
(declare-fun <NR_PPCall> () NextRecv<>)
(declare-fun <NR_Unknown> () NextRecv<>)
(assert (distinct <NR_Notification> <NR_PPCall> <NR_Unknown>))
(define-fun NextRecv.<> ((v NextRecv)) NextRecv<> ((_ extract 71 70) v))
(define-fun NR_Notification.1 ((v NextRecv)) Ch_set ((_ extract 69 6) v))
(define-fun NR_Notification ((a Ch_set)) NextRecv (concat <NR_Notification> (concat a (_ bv0 6))))
(define-fun NR_PPCall.1 ((v NextRecv)) Prod_Ch_MsgInfo ((_ extract 69 0) v))
(define-fun NR_PPCall ((a Prod_Ch_MsgInfo)) NextRecv (concat <NR_PPCall> a))
(define-fun NR_Unknown () NextRecv (concat <NR_Unknown> (_ bv0 70)))

(define-sort Maybe_MsgInfo () (_ BitVec 65))
(define-sort Maybe_MsgInfo<> () (_ BitVec 1))
(declare-fun <MsgInfo_Nothing> () Maybe_MsgInfo<>)
(declare-fun <MsgInfo_Just> () Maybe_MsgInfo<>)
(assert (distinct <MsgInfo_Nothing> <MsgInfo_Just>))
(define-fun Maybe_MsgInfo.<> ((v Maybe_MsgInfo)) Maybe_MsgInfo<> ((_ extract 64 64) v))
(define-fun MsgInfo_Nothing () Maybe_MsgInfo (concat <MsgInfo_Nothing> (_ bv0 64)))
(define-fun MsgInfo_Just.1 ((v Maybe_MsgInfo)) MsgInfo ((_ extract 63 0) v))
(define-fun MsgInfo_Just ((a MsgInfo)) Maybe_MsgInfo (concat <MsgInfo_Just> a))

(define-sort Maybe_Prod_Ch_MsgInfo () (_ BitVec 71))
(define-sort Maybe_Prod_Ch_MsgInfo<> () (_ BitVec 1))
(declare-fun <Prod_Ch_MsgInfo_Nothing> () Maybe_Prod_Ch_MsgInfo<>)
(declare-fun <Prod_Ch_MsgInfo_Just> () Maybe_Prod_Ch_MsgInfo<>)
(assert (distinct <Prod_Ch_MsgInfo_Nothing> <Prod_Ch_MsgInfo_Just>))
(define-fun Maybe_Prod_Ch_MsgInfo.<> ((v Maybe_Prod_Ch_MsgInfo)) Maybe_Prod_Ch_MsgInfo<> ((_ extract 70 70) v))
(define-fun Prod_Ch_MsgInfo_Nothing () Maybe_Prod_Ch_MsgInfo (concat <Prod_Ch_MsgInfo_Nothing> (_ bv0 70)))
(define-fun Prod_Ch_MsgInfo_Just.1 ((v Maybe_Prod_Ch_MsgInfo)) Prod_Ch_MsgInfo ((_ extract 69 0) v))
(define-fun Prod_Ch_MsgInfo_Just ((a Prod_Ch_MsgInfo)) Maybe_Prod_Ch_MsgInfo (concat <Prod_Ch_MsgInfo_Just> a))

; data PlatformContext = LC
;   { lc_running_pd :: PD
;   , lc_receive_oracle :: NextRecv
;   , lc_unhandled_notified :: Ch_set
;   , lc_last_handled_notified :: Ch_set
;   , lc_unhandled_ppcall :: Maybe_Prod_Ch_MsgInfo
;   , lc_unhandled_reply :: Maybe_MsgInfo
;   , lc_last_handled_reply :: Maybe_MsgInfo
;   }
(define-sort PlatformContext () (_ BitVec 407))
(define-fun LC ((a PD) (b NextRecv) (c Ch_set) (d Ch_set) (e Maybe_Prod_Ch_MsgInfo) (f Maybe_MsgInfo) (g Maybe_MsgInfo)) PlatformContext (concat a (concat b (concat c (concat d (concat e (concat f g)))))))
(define-fun lc_running_pd ((c PlatformContext)) PD ((_ extract 406 401) c))
(define-fun lc_running_pd= ((c PlatformContext) (v PD)) PlatformContext (concat v ((_ extract 400 0) c)))
(define-fun lc_receive_oracle ((c PlatformContext)) NextRecv ((_ extract 400 329) c))
(define-fun lc_receive_oracle= ((c PlatformContext) (v NextRecv)) PlatformContext (concat ((_ extract 406 401) c) (concat v ((_ extract 328 0) c))))
(define-fun lc_unhandled_notified ((c PlatformContext)) Ch_set ((_ extract 328 265) c))
(define-fun lc_unhandled_notified= ((c PlatformContext) (v Ch_set)) PlatformContext (concat ((_ extract 406 329) c) (concat v ((_ extract 264 0) c))))
(define-fun lc_last_handled_notified ((c PlatformContext)) Ch_set ((_ extract 264 201) c))
(define-fun lc_last_handled_notified= ((c PlatformContext) (v Ch_set)) PlatformContext (concat ((_ extract 406 265) c) (concat v ((_ extract 200 0) c))))
(define-fun lc_unhandled_ppcall ((c PlatformContext)) Maybe_Prod_Ch_MsgInfo ((_ extract 200 130) c))
(define-fun lc_unhandled_ppcall= ((c PlatformContext) (v Maybe_Prod_Ch_MsgInfo)) PlatformContext (concat ((_ extract 406 201) c) (concat v ((_ extract 129 0) c))))
(define-fun lc_unhandled_reply ((c PlatformContext)) Maybe_MsgInfo ((_ extract 129 65) c))
(define-fun lc_unhandled_reply= ((c PlatformContext) (v Maybe_MsgInfo)) PlatformContext (concat ((_ extract 406 130) c) (concat v ((_ extract 64 0) c))))
(define-fun lc_last_handled_reply ((c PlatformContext)) Maybe_MsgInfo ((_ extract 64 0) c))
(define-fun lc_last_handled_reply= ((c PlatformContext) (v Maybe_MsgInfo)) PlatformContext (concat ((_ extract 406 65) c) v))

(define-fun C_channel_to_SMT_channel ((cc (_ BitVec 32))) Ch ((_ extract 5 0) cc))
(define-fun C_channel_valid ((cc (_ BitVec 32))) Bool (bvule cc (_ bv62 32)))
(define-fun C_msg_info_to_SMT_msg_info ((mi (_ BitVec 64))) MsgInfo mi)
; to compare msg info, just use equality, all the bits are significant
; only compares the label field
; end of prelude
