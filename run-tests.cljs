#!/usr/bin/env nbb
(ns run-tests
  (:require [cljs.test :refer [run-tests]]
            [delta.op-test]))

(defmethod cljs.test/report [:cljs.test/default :end-run-tests] [m]
  (when-not (cljs.test/successful? m)
    (js/process.exit 1)))

(run-tests 'delta.op-test)
