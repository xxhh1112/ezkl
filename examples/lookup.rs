#[macro_use]
extern crate criterion;

use ezkl::pfsys::evm::aggregation::AggregationCircuit;
use ezkl::pfsys::Snark;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::dev::MockProver;
use halo2_proofs::plonk::*;
use halo2_proofs::poly::kzg::strategy::AccumulatorStrategy;
use halo2_proofs::poly::{commitment::ParamsProver, Rotation};
use halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2curves::ff::PrimeField;
use halo2curves::pairing::Engine;
use std::io::Write;

use halo2_proofs::poly::kzg::commitment::ParamsKZG;

use std::marker::PhantomData;

const K: u32 = 10;

fn main() {
    #[derive(Clone, Default)]
    struct MyCircuit<F: PrimeField> {
        _marker: PhantomData<F>,
    }

    #[derive(Clone)]
    struct MyConfig {
        qlookup: Selector,
        table_inputs: [TableColumn; 2],
        table_outputs: [TableColumn; 2],
        advice: Column<Advice>,
        other_advice: Column<Advice>,
        other_other_advice: Column<Advice>,
    }

    impl<F: PrimeField> Circuit<F> for MyCircuit<F> {
        type Config = MyConfig;
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> MyConfig {
            let config = MyConfig {
                qlookup: meta.complex_selector(),
                table_inputs: [meta.lookup_table_column(), meta.lookup_table_column()],
                table_outputs: [meta.lookup_table_column(), meta.lookup_table_column()],
                advice: meta.advice_column(),
                other_advice: meta.advice_column(),
                other_other_advice: meta.advice_column(),
            };

            meta.enable_equality(config.advice);
            meta.enable_equality(config.other_advice);
            meta.enable_equality(config.other_other_advice);

            let default_xs = vec![F::from(0), F::from(2_u64.pow(K - 2))];
            let default_ys = vec![F::from(0), F::from(2_u64.pow(K - 1))];

            for col_idx in 0..2 {
                let _ = meta.lookup("", |cs| {
                    let sel = cs.query_selector(config.qlookup.clone());
                    let synthetic_idx = cs.query_advice(config.other_other_advice, Rotation(0));
                    let synthetic_sel = vec![
                        // 1 if synthetic_idx == 0
                        Expression::Constant(F::from(1)) - synthetic_idx.clone(),
                        // 1 if synthetic_idx == 1
                        synthetic_idx.clone(),
                        // if it's not 0 or 1 then both expressions will be =/= 0 which breaks the lookup table, preventing malicious (non-boolean) inputs
                    ];

                    let (default_x, default_y): (F, F) = (default_xs[col_idx], default_ys[col_idx]);

                    // we index from 1 to avoid the zero element creating soundness issues
                    // this is 0 if the index is the same as the column index (starting from 1)
                    let col_expr = sel.clone() * synthetic_sel[col_idx].clone();
                    // !!!!!! remove this when we expand beyond 2 columns !!!!!!!!!
                    let not_expr = Expression::Constant(F::from(1)) - col_expr.clone();

                    vec![
                        (
                            col_expr.clone() * cs.query_advice(config.advice, Rotation(0))
                                + not_expr.clone() * default_x,
                            config.table_inputs[col_idx],
                        ),
                        (
                            col_expr * cs.query_advice(config.other_advice, Rotation(0))
                                + not_expr * default_y,
                            config.table_outputs[col_idx],
                        ),
                    ]
                });
            }

            config
        }

        fn synthesize(
            &self,
            config: MyConfig,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            layouter.assign_table(
                || "8-bit 2x table",
                |mut table| {
                    for row in 0u64..2_u64.pow(K - 2) {
                        table.assign_cell(
                            || format!("input row {}", row),
                            config.table_inputs[0],
                            row as usize,
                            || Value::known(F::from(row)),
                        )?;
                        // table output (2x the input) -- yeehaw
                        table.assign_cell(
                            || format!("output row {}", row),
                            config.table_outputs[0],
                            row as usize,
                            || Value::known(F::from(2 * row)),
                        )?;
                    }
                    // different set of inputs
                    for (i, row) in (2_u64.pow(K - 2)..2_u64.pow(K - 1)).enumerate() {
                        table.assign_cell(
                            || format!("input row {}", row),
                            config.table_inputs[1],
                            i,
                            || Value::known(F::from(row)),
                        )?;
                        // table output (2x the input) -- yeehaw
                        table.assign_cell(
                            || format!("output row {}", row),
                            config.table_outputs[1],
                            i,
                            || Value::known(F::from(2 * row)),
                        )?;
                    }

                    Ok(())
                },
            )?;

            layouter.assign_region(
                || "assign values",
                |mut region| {
                    for offset in 0u64..2_u64.pow(K - 2) {
                        // enable the 2x lookup table selector
                        config.qlookup.enable(&mut region, offset as usize)?;
                        // input
                        region.assign_advice(
                            || format!("offset {}", offset),
                            config.advice,
                            offset as usize,
                            || Value::known(F::from(offset)),
                        )?;

                        // 2x
                        region.assign_advice(
                            || format!("offset {}", offset),
                            config.other_advice,
                            offset as usize,
                            || Value::known(F::from(2 * offset)),
                        )?;

                        // we're in the first lookup table
                        region.assign_advice(
                            || format!("offset {}", offset),
                            config.other_other_advice,
                            offset as usize,
                            || Value::known(F::from(0)),
                        )?;
                    }

                    for offset in 2_u64.pow(K - 2)..2_u64.pow(K - 1) {
                        // enable the 2x lookup table selector
                        config.qlookup.enable(&mut region, offset as usize)?;
                        // input
                        region.assign_advice(
                            || format!("offset {}", offset),
                            config.advice,
                            offset as usize,
                            || Value::known(F::from(offset)),
                        )?;

                        // 2x
                        region.assign_advice(
                            || format!("offset {}", offset),
                            config.other_advice,
                            offset as usize,
                            || Value::known(F::from(2 * offset)),
                        )?;

                        // we're in the second lookup table
                        region.assign_advice(
                            || format!("offset {}", offset),
                            config.other_other_advice,
                            offset as usize,
                            || Value::known(F::from(1)),
                        )?;
                    }

                    Ok(())
                },
            )
        }
    }

    fn keygen(k: u32) -> (ParamsKZG<Bn256>, ProvingKey<G1Affine>) {
        let params: ParamsKZG<Bn256> = ParamsKZG::new(k);
        let empty_circuit: MyCircuit<<Bn256 as Engine>::Scalar> = MyCircuit {
            _marker: PhantomData,
        };
        let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");
        (params, pk)
    }

    fn mock_prover(k: u32) {
        let circuit: MyCircuit<<Bn256 as Engine>::Scalar> = MyCircuit {
            _marker: PhantomData,
        };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify_par(), Ok(()))
    }

    fn mock_aggr_prover(k: u32, snarks: Vec<Snark<Fr, G1Affine>>) {
        let circuit = AggregationCircuit::new(&G1Affine::generator().into(), snarks).unwrap();

        let prover =
            halo2_proofs::dev::MockProver::run(k, &circuit, vec![circuit.instances()]).unwrap();
        prover.verify_par().unwrap()
    }

    fn prover(
        _k: u32,
        params: &ParamsKZG<Bn256>,
        pk: &ProvingKey<G1Affine>,
    ) -> Snark<Fr, G1Affine> {
        let circuit: MyCircuit<<Bn256 as Engine>::Scalar> = MyCircuit {
            _marker: PhantomData,
        };

        let strategy = AccumulatorStrategy::new(params);
        ezkl::pfsys::create_proof_circuit_kzg(
            circuit,
            &params,
            vec![],
            &pk,
            ezkl::pfsys::TranscriptType::Poseidon,
            strategy,
            // this means we'll also verify the proof
            ezkl::circuit::CheckMode::SAFE,
        )
        .unwrap()
    }

    env_logger::init();

    println!("k = {}", K);

    println!("mock prover");
    let start = std::time::Instant::now();
    mock_prover(K);
    let end = std::time::Instant::now();
    println!("mock prover time: {:?}", end.duration_since(start));
    // time it
    println!("keygen");
    let start = std::time::Instant::now();
    let (params, pk) = keygen(K);
    let end = std::time::Instant::now();
    println!("keygen time: {:?}", end.duration_since(start));

    println!("saving proving key 💾");

    let path = "pk.key";

    let f = std::fs::File::create(path).unwrap();
    let mut writer = std::io::BufWriter::new(f);
    pk.write(&mut writer, halo2_proofs::SerdeFormat::RawBytes)
        .unwrap();
    writer.flush().unwrap();

    println!("saving verifier key 💾");

    let vk = pk.get_vk();

    let path = "vk.key";

    let f = std::fs::File::create(path).unwrap();
    let mut writer = std::io::BufWriter::new(f);
    vk.write(&mut writer, halo2_proofs::SerdeFormat::RawBytes)
        .unwrap();
    writer.flush().unwrap();

    // time it
    println!("prover");
    let start = std::time::Instant::now();
    let proof = prover(K, &params, &pk);
    let end = std::time::Instant::now();
    println!("prover time: {:?}", end.duration_since(start));
    // time it
    println!("verifier");

    mock_aggr_prover(20, vec![proof]);
}
