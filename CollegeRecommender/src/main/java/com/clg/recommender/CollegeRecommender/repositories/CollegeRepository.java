package com.clg.recommender.CollegeRecommender.repositories;

import com.clg.recommender.CollegeRecommender.model.Branch;
import com.clg.recommender.CollegeRecommender.model.Colloge;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface CollegeRepository extends JpaRepository<Colloge, Integer> {
}
