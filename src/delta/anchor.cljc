(ns delta.anchor
  "⑱ Structural anchors for kotoba-delta ops (ADR-2607161325 / ADR-2607160005).

  DeltaDB's headline property is 'references survive as the code moves'.
  For a Clojure/EDN codebase the natural stable identity is not a line
  number but the DEFINITION: a top-level form's (kind, name) plus a content
  hash of its own text. An op anchored to a definition resolves to the same
  definition after unrelated code is inserted/removed elsewhere — a line
  anchor would break, this doesn't.

  Pure cljc. Uses a balanced-delimiter top-level splitter (robust across
  reader conditionals / metadata that trip a naive reader), not the full
  Clojure reader — we only need to locate top-level def forms."
  (:require [clojure.string :as str]))

(defn top-level-forms
  "Split source into top-level forms with their char offsets, skipping
  strings, chars, and ; line comments. -> [{:text :start :end} ...]"
  [src]
  (let [n (count src)]
    (loop [i 0 depth 0 start nil forms [] in-str? false esc? false]
      (if (>= i n)
        forms
        (let [c (nth src i)]
          (cond
            in-str? (recur (inc i) depth start forms
                           (not (and (not esc?) (= c \"))) (and (not esc?) (= c \\)))
            (= c \;) (recur (loop [j i] (if (or (>= j n) (= (nth src j) \newline)) j (recur (inc j))))
                            depth start forms false false)
            (= c \") (recur (inc i) depth (or start i) forms true false)
            (or (= c \() (= c \[) (= c \{))
            (recur (inc i) (inc depth) (if (zero? depth) i start) forms false false)
            (or (= c \)) (= c \]) (= c \}))
            (let [d (dec depth)]
              (if (zero? d)
                (recur (inc i) 0 nil (conj forms {:text (subs src start (inc i))
                                                  :start start :end (inc i)}) false false)
                (recur (inc i) d start forms false false)))
            :else (recur (inc i) depth start forms false false)))))))

(defn- def-form?
  "If a top-level form text is a (def...|defn...|defn-...|defmethod...) with a
  name, return {:kind :name}, else nil."
  [text]
  ;; optional metadata is only a ^-prefixed token; the name is the first
  ;; symbol after (defn / def / defn- / defmethod, possibly past one ^meta.
  (when-let [[_ kind nm] (re-find #"^\(\s*(def[a-z-]*|defmethod)\s+(?:\^\S+\s+)?([A-Za-z*!?<>=+_.-][\w*!?<>=+.:/-]*)" text)]
    {:kind kind :name nm}))

(defn definitions
  "All top-level definitions in src with content hashes. hash-fn injected.
  -> [{:kind :name :hash :start :end :text} ...]"
  [hash-fn src]
  (->> (top-level-forms src)
       (keep (fn [{:keys [text] :as f}]
               (when-let [d (def-form? text)]
                 (merge f d {:hash (hash-fn (str/trim text))}))))
       vec))

(defn anchor-of
  "Anchor for a definition by name: {:anchor/kind :anchor/name :anchor/hash}.
  The hash pins the exact content at anchoring time; resolving later reports
  whether it's unchanged, moved (same hash, new offset), or edited."
  [hash-fn src def-name]
  (when-let [d (first (filter #(= def-name (:name %)) (definitions hash-fn src)))]
    {:anchor/kind (:kind d) :anchor/name (:name d) :anchor/hash (:hash d)}))

(defn resolve-anchor
  "Resolve an anchor against a (possibly changed) source.
  -> {:found? :status :start :end} where :status ∈
     :unchanged (name present, same hash)
     :moved     (name present, same hash, different offset — code moved)
     :edited    (name present, hash differs — definition body changed)
     :gone      (name absent)."
  [hash-fn src {:anchor/keys [name hash]} & [prev-start]]
  (if-let [d (first (filter #(= name (:name %)) (definitions hash-fn src)))]
    {:found? true
     :status (cond
               (not= hash (:hash d)) :edited
               (and prev-start (not= prev-start (:start d))) :moved
               :else :unchanged)
     :start (:start d) :end (:end d)}
    {:found? false :status :gone}))
