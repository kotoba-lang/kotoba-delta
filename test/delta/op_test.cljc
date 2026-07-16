(ns delta.op-test
  (:require [clojure.test :refer [deftest is testing]]
            [delta.op :as op]))

(def fake-hash #(str "H" (hash %)))
(defn fake-sign [pub payload] (str "SIG:" pub ":" (fake-hash payload)))
(defn fake-verify [pub payload sig] (= sig (fake-sign pub payload)))

(defn signed [prev-op m]
  (let [o (op/make-op (assoc m :parent (when prev-op (op/op-id fake-hash prev-op))
                             :actor "did:key:zA" :at "2026-07-16T00:00:00Z"))]
    {:op o :sig (fake-sign "pkA" (op/canonical-str o))}))

(def ctx {:verify-fn fake-verify :hash-fn fake-hash
          :actor-pubkey "pkA" :grant-ok? true})

(deftest op-chain-admission
  (let [w (signed nil {:kind :write :file "a.cljc" :new "(ns a)\n(def x 1)\n"})
        e (signed (:op w) {:kind :edit :file "a.cljc" :old "(def x 1)" :new "(def x 2)"})]
    (testing "genesis + chained accept"
      (is (= :accept (:verdict (op/admit w (assoc ctx :head nil)))))
      (is (= :accept (:verdict (op/admit e (assoc ctx :head w))))))
    (testing "parent mismatch (replay) rejected"
      (is (some #{:parent-mismatch} (:reasons (op/admit e (assoc ctx :head e))))))
    (testing "tamper rejected"
      (let [t (assoc-in e [:op :op/new] "(def x 666)")]
        (is (some #{:bad-signature} (:reasons (op/admit t (assoc ctx :head w)))))))
    (testing "no grant rejected"
      (is (some #{:unauthorized-actor}
                (:reasons (op/admit w (assoc ctx :head nil :grant-ok? false))))))
    (testing "secret material rejected before entering the log"
      (let [s (signed (:op e) {:kind :write :file ".env"
                               :new "API_KEY=abcdefghijklmnopqrstuvwx1234"})]
        (is (some #{:secret-material} (:reasons (op/admit s (assoc ctx :head e)))))))))

(deftest replay-determinism-and-conflicts
  (let [ops [(op/make-op {:actor "a" :at "t" :kind :write :file "a" :new "one two three"})
             (op/make-op {:actor "a" :at "t" :kind :edit :file "a" :old "two" :new "2"})
             (op/make-op {:actor "a" :at "t" :kind :write :file "b" :new "bee"})]]
    (testing "deterministic: same ops -> same files -> same content hash"
      (let [r1 (op/replay {} ops) r2 (op/replay {} ops)]
        (is (= 3 (:applied r1)))
        (is (= {"a" "one 2 three" "b" "bee"} (:files r1)))
        (is (= (op/content-hash fake-hash (:files r1))
               (op/content-hash fake-hash (:files r2))))))
    (testing "explicit conflict: old-not-found stops replay, never guesses"
      (let [bad (conj ops (op/make-op {:actor "a" :at "t" :kind :edit :file "a"
                                       :old "two" :new "again"}))
            r (op/replay {} bad)]
        (is (= 3 (:applied r)))
        (is (= :old-not-found (get-in r [:conflict :reason])))))
    (testing "ambiguous old is a conflict (Edit-tool semantics)"
      (let [r (op/replay {"f" "x x"} [(op/make-op {:actor "a" :at "t" :kind :edit
                                                   :file "f" :old "x" :new "y"})])]
        (is (= :ambiguous-old (get-in r [:conflict :reason])))))
    (testing "remove missing file is a conflict"
      (is (= :file-not-found
             (get-in (op/replay {} [(op/make-op {:actor "a" :at "t" :kind :remove :file "z"})])
                     [:conflict :reason]))))))
